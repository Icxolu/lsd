use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use windows::Win32::Foundation::PSID;
use windows::Win32::Security;

use super::{Owner, Permissions};

const BUF_SIZE: u32 = 256;

pub fn get_file_data(path: &Path) -> Result<(Owner, Permissions), io::Error> {
    // Overall design:
    // This function allocates some data with GetNamedSecurityInfoW,
    // manipulates it only through WinAPI calls (treating the pointers as
    // opaque) and then frees it at the end with LocalFree.
    //
    // For memory safety, the critical things are:
    // - No pointer is valid before the return value of GetNamedSecurityInfoW
    //   is checked
    // - LocalFree must be called before returning
    // - No pointer is valid after the call to LocalFree

    let mut psd = SecurityDescriptor::new(path)?;

    // SAFETY: the sid is valid until `psd` drops, which is at the end of the
    // function
    let owner = match unsafe { lookup_account_sid(psd.owner_sid()) } {
        Ok((n, d)) => {
            let owner_name = os_from_buf(&n);
            let owner_domain = os_from_buf(&d);

            format!(
                "{}\\{}",
                owner_domain.to_string_lossy(),
                &owner_name.to_string_lossy()
            )
        }
        Err(_) => String::from("-"),
    };

    // SAFETY: the sid is valid until `psd` drops, which is at the end of the
    // function
    let group = match unsafe { lookup_account_sid(psd.group_sid()) } {
        Ok((n, d)) => {
            let group_name = os_from_buf(&n);
            let group_domain = os_from_buf(&d);

            format!(
                "{}\\{}",
                group_domain.to_string_lossy(),
                &group_name.to_string_lossy()
            )
        }
        Err(_) => String::from("-"),
    };

    // This structure will be returned
    let owner = Owner::new(owner, group);

    // Get the size and allocate bytes for a 1-sub-authority SID
    // 1 sub-authority because the Windows World SID is always S-1-1-0, with
    // only a single sub-authority.
    //
    // Assumptions: None
    // "This function cannot fail"
    //     -- Windows Dev Center docs
    let mut world_sid_len: u32 = unsafe { Security::GetSidLengthRequired(1) };
    let mut world_sid = vec![0u8; world_sid_len as usize];
    let world_sid_ptr = PSID(world_sid.as_mut_ptr() as *mut _);

    // Assumptions:
    // - world_sid_len is no larger than the number of bytes available at
    //   world_sid
    // - world_sid is appropriately aligned (if there are strange crashes this
    //   might be why)
    unsafe {
        Security::CreateWellKnownSid(
            Security::WinWorldSid,
            PSID::default(),
            world_sid_ptr,
            &mut world_sid_len,
        )
    }
    .ok()?;

    // SAFETY:
    // The `sid`s are valid for until the end of this function, when `psd` and
    // `world_sid` drop
    let owner_access_mask = unsafe { get_acl_access_mask(psd.owner_sid(), &mut psd) }?;
    let group_access_mask = unsafe { get_acl_access_mask(psd.group_sid(), &mut psd) }?;
    let world_access_mask = unsafe { get_acl_access_mask(world_sid_ptr, &mut psd) }?;

    let permissions = {
        use windows::Win32::Storage::FileSystem::{
            FILE_ACCESS_FLAGS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };
        let has_bit = |field: u32, bit: FILE_ACCESS_FLAGS| field & bit.0 != 0;
        Permissions {
            user_read: has_bit(owner_access_mask, FILE_GENERIC_READ),
            user_write: has_bit(owner_access_mask, FILE_GENERIC_WRITE),
            user_execute: has_bit(owner_access_mask, FILE_GENERIC_EXECUTE),

            group_read: has_bit(group_access_mask, FILE_GENERIC_READ),
            group_write: has_bit(group_access_mask, FILE_GENERIC_WRITE),
            group_execute: has_bit(group_access_mask, FILE_GENERIC_EXECUTE),

            other_read: has_bit(world_access_mask, FILE_GENERIC_READ),
            other_write: has_bit(world_access_mask, FILE_GENERIC_WRITE),
            other_execute: has_bit(world_access_mask, FILE_GENERIC_EXECUTE),

            sticky: false,
            setuid: false,
            setgid: false,
        }
    };

    Ok((owner, permissions))
}

/// SAFETY: `psid` is valid for the entire function execution
unsafe fn get_acl_access_mask<P>(psid: P, psd: &mut SecurityDescriptor) -> Result<u32, io::Error>
where
    P: Into<PSID>,
{
    let mut manager = AuthzResourceManager::new()?;
    let mut context = AuthzClientContext::new(&mut manager, psid.into())?;
    let mask = authz_access_check(&mut context, psd)?;

    Ok(mask)
}

fn authz_access_check(
    context: &mut AuthzClientContext,
    psd: &mut SecurityDescriptor,
) -> Result<u32, io::Error> {
    let prequest = Security::Authorization::AUTHZ_ACCESS_REQUEST {
        DesiredAccess: windows::Win32::System::SystemServices::MAXIMUM_ALLOWED,
        ..Default::default()
    };

    let mut buffer = [0u32; 2];
    let mut preply = Security::Authorization::AUTHZ_ACCESS_REPLY {
        ResultListLength: 1,
        GrantedAccessMask: buffer.as_mut_ptr(),
        // SAFETY: The resulting pointer is in bounds and the offset doesnt overflow an isize
        Error: unsafe { buffer.as_mut_ptr().offset(1) },
        ..Default::default()
    };

    unsafe {
        Security::Authorization::AuthzAccessCheck(
            Security::Authorization::AUTHZ_ACCESS_CHECK_FLAGS::default(),
            context.0,
            &prequest,
            None,
            psd.psd,
            None,
            &mut preply,
            None,
        )
    }
    .ok()?;

    Ok(buffer[0])
}

/// Get a username and domain name from a SID
///
/// Assumption: sid is a valid pointer that remains valid through the entire
/// function execution
///
/// Returns null-terminated Vec's, one for the name and one for the domain.
unsafe fn lookup_account_sid(sid: PSID) -> Result<(Vec<u16>, Vec<u16>), std::io::Error> {
    let mut name_size: u32 = BUF_SIZE;
    let mut domain_size: u32 = BUF_SIZE;

    loop {
        let mut name: Vec<u16> = vec![0; name_size as usize];
        let mut domain: Vec<u16> = vec![0; domain_size as usize];

        let old_name_size = name_size;
        let old_domain_size = domain_size;

        let mut sid_name_use = MaybeUninit::uninit();

        // Assumptions:
        // - sid is a valid pointer to a SID data structure
        // - name_size and domain_size accurately reflect the sizes
        //
        // TODO: maybe we can save time here by using `LookupAccountSidLocalW`
        // which was added to the win32metadata in win32metadata#950 and
        // hopefully will be available in the next release of windows-rs
        let result = Security::LookupAccountSidW(
            None,
            sid,
            windows::core::PWSTR(name.as_mut_ptr()),
            &mut name_size,
            windows::core::PWSTR(domain.as_mut_ptr()),
            &mut domain_size,
            sid_name_use.as_mut_ptr(),
        );

        if result.ok().is_ok() {
            // Success!
            return Ok((name, domain));
        } else if name_size != old_name_size || domain_size != old_domain_size {
            // Need bigger buffers
            // name_size and domain_size are already set, just loop
            continue;
        } else {
            // Unknown account and or system domain identification
            // Possibly foreign item originating from another machine
            // TODO: Calculate permissions since it has to be possible if Explorer knows.
            return Err(io::Error::from_raw_os_error(
                windows::Win32::Foundation::GetLastError().0 as i32,
            ));
        }
    }
}

/// Create an `OsString` from a NUL-terminated buffer
///
/// Decodes the WTF-16 encoded buffer until it hits a NUL (code point 0).
/// Everything after and including that code point is not included.
fn os_from_buf(buf: &[u16]) -> OsString {
    OsString::from_wide(
        &buf.iter()
            .cloned()
            .take_while(|&n| n != 0)
            .collect::<Vec<u16>>(),
    )
}

/// Create a WTF-16-encoded NUL-terminated buffer from an `OsStr`.
///
/// Decodes the `OsStr`, then appends a NUL.
fn buf_from_os(os: &OsStr) -> Vec<u16> {
    let mut buf: Vec<u16> = os.encode_wide().collect();
    buf.push(0);
    buf
}

/// Checks wether the given [`FILE_FLAGS_AND_ATTRIBUTES`] are set for the given
/// [`Path`]
///
/// [`FILE_FLAGS_AND_ATTRIBUTES`]: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES
#[inline]
fn has_path_attribute(
    path: &Path,
    flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) -> bool {
    let windows_path = buf_from_os(path.as_os_str());
    let file_attributes = unsafe {
        windows::Win32::Storage::FileSystem::GetFileAttributesW(windows::core::PCWSTR(
            windows_path.as_ptr(),
        ))
    };
    file_attributes & flags.0 > 0
}

/// Checks whether the windows [`hidden`] attribute is set for the given
/// [`Path`]
///
/// [`hidden`]: windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN
pub fn is_path_hidden(path: &Path) -> bool {
    has_path_attribute(
        path,
        windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN,
    )
}

/// Checks whether the windows [`system`] attribute is set for the given
/// [`Path`]
///
/// [`system`]: windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SYSTEM
pub fn is_path_system(path: &Path) -> bool {
    has_path_attribute(
        path,
        windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SYSTEM,
    )
}

struct AuthzResourceManager(Security::Authorization::AUTHZ_RESOURCE_MANAGER_HANDLE);

impl AuthzResourceManager {
    fn new() -> Result<Self, io::Error> {
        let mut handle = Security::Authorization::AUTHZ_RESOURCE_MANAGER_HANDLE::default();
        unsafe {
            Security::Authorization::AuthzInitializeResourceManager(
                Security::Authorization::AUTHZ_RM_FLAG_NO_AUDIT.0,
                None,
                None,
                None,
                None,
                &mut handle,
            )
        }
        .ok()?;

        Ok(Self(handle))
    }
}

impl Drop for AuthzResourceManager {
    fn drop(&mut self) {
        let _ = unsafe { Security::Authorization::AuthzFreeResourceManager(self.0) };
    }
}

struct AuthzClientContext<'a>(
    Security::Authorization::AUTHZ_CLIENT_CONTEXT_HANDLE,
    std::marker::PhantomData<&'a mut ()>,
);

impl<'a> AuthzClientContext<'a> {
    /// SAFETY:
    /// psid is valid for the lifetime of the context
    unsafe fn new(manager: &'a mut AuthzResourceManager, sid: PSID) -> Result<Self, io::Error> {
        let mut handle = Security::Authorization::AUTHZ_CLIENT_CONTEXT_HANDLE::default();
        Security::Authorization::AuthzInitializeContextFromSid(
            0,
            sid,
            manager.0,
            None,
            Default::default(),
            None,
            &mut handle,
        )
        .ok()?;

        Ok(Self(handle, std::marker::PhantomData))
    }
}

impl<'a> Drop for AuthzClientContext<'a> {
    fn drop(&mut self) {
        let _ = unsafe { Security::Authorization::AuthzFreeContext(self.0) };
    }
}

struct SecurityDescriptor {
    owner_sid: PSID,
    group_sid: PSID,
    // drop the psd last, since the SIDs point into it
    psd: Security::PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn new(path: &Path) -> Result<Self, io::Error> {
        let windows_path = buf_from_os(path.as_os_str());
        let mut owner_sid = Default::default();
        let mut group_sid = Default::default();
        let mut psd = Security::PSECURITY_DESCRIPTOR::default();

        unsafe {
            Security::Authorization::GetNamedSecurityInfoW(
                windows::core::PCWSTR::from_raw(windows_path.as_ptr()),
                Security::Authorization::SE_FILE_OBJECT,
                Security::OWNER_SECURITY_INFORMATION | Security::GROUP_SECURITY_INFORMATION,
                Some(&mut owner_sid),
                Some(&mut group_sid),
                None,
                None,
                &mut psd,
            )
        }
        .ok()?;

        Ok(Self {
            owner_sid,
            group_sid,
            psd,
        })
    }

    /// SAFETY:  
    /// The returned [`PSID`] must only be used during the lifetime of the
    /// [`SecurityDescriptor`]
    unsafe fn owner_sid(&mut self) -> PSID {
        self.owner_sid
    }

    /// SAFETY:  
    /// The returned [`PSID`] must only be used during the lifetime of the
    /// [`SecurityDescriptor`]
    unsafe fn group_sid(&mut self) -> PSID {
        self.group_sid
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { windows::Win32::System::Memory::LocalFree(self.psd.0 as _) };
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_wtf16_behavior() {
        let basic_os = OsString::from("TeSt");
        let basic_buf = vec![0x54, 0x65, 0x53, 0x74, 0x00];
        let basic_buf_nuls = vec![0x54, 0x65, 0x53, 0x74, 0x00, 0x00, 0x00, 0x00];

        assert_eq!(os_from_buf(&basic_buf), basic_os);
        assert_eq!(buf_from_os(&basic_os), basic_buf);
        assert_eq!(os_from_buf(&basic_buf_nuls), basic_os);

        let unicode_os = OsString::from("💩");
        let unicode_buf = vec![0xd83d, 0xdca9, 0x0];
        let unicode_buf_nuls = vec![0xd83d, 0xdca9, 0x0, 0x0, 0x0, 0x0, 0x0];

        assert_eq!(os_from_buf(&unicode_buf), unicode_os);
        assert_eq!(buf_from_os(&unicode_os), unicode_buf);
        assert_eq!(os_from_buf(&unicode_buf_nuls), unicode_os);
    }

    #[test]
    fn every_wtf16_codepair_roundtrip() {
        for lsb in 0..256u16 {
            let mut vec: Vec<u16> = Vec::with_capacity(257);

            for msb in 0..=256u16 {
                let val = msb << 8 | lsb;

                if val != 0 {
                    vec.push(val)
                }
            }

            vec.push(0);

            let os = os_from_buf(&vec);
            let new_vec = buf_from_os(&os);

            assert_eq!(&vec, &new_vec);
        }
    }
}
