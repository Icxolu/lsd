use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use windows::Win32::Foundation::PSID;
use windows::Win32::Security::{self, Authorization::TRUSTEE_W, ACL};

use super::{Owner, Permissions};

const BUF_SIZE: u32 = 256;

pub(super) struct SecurityInfo {
    owner_sid_ptr: PSID,
    group_sid_ptr: PSID,
    dacl_ptr: *mut ACL,
    sd_ptr: Security::PSECURITY_DESCRIPTOR,
}

impl SecurityInfo {
    pub(super) fn new(path: &Path) -> io::Result<Self> {
        let windows_path = buf_from_os(path.as_os_str());

        let mut owner_sid_ptr = MaybeUninit::uninit();
        let mut group_sid_ptr = MaybeUninit::uninit();
        let mut dacl_ptr = MaybeUninit::uninit();
        let mut sd_ptr = MaybeUninit::uninit();

        // Assumptions:
        // - windows_path is a null-terminated WTF-16-encoded string
        // - The return value is checked against ERROR_SUCCESS before pointers are used
        // - All pointers are opaque and should only be used with WinAPI calls
        // - Pointers are only valid if their corresponding X_SECURITY_INFORMATION
        //   flags are set
        // - sd_ptr must be freed with LocalFree
        unsafe {
            Security::Authorization::GetNamedSecurityInfoW(
                windows::core::PCWSTR::from_raw(windows_path.as_ptr()),
                Security::Authorization::SE_FILE_OBJECT,
                Security::OWNER_SECURITY_INFORMATION
                    | Security::GROUP_SECURITY_INFORMATION
                    | Security::DACL_SECURITY_INFORMATION,
                Some(owner_sid_ptr.as_mut_ptr()),
                Some(group_sid_ptr.as_mut_ptr()),
                Some(dacl_ptr.as_mut_ptr()),
                None,
                sd_ptr.as_mut_ptr(),
            )
        }
        .ok()?;

        // Assumptions:
        // - owner_sid_ptr is valid
        // - group_sid_ptr is valid
        // (both OK because GetNamedSecurityInfoW returned success)
        let owner_sid_ptr = unsafe { owner_sid_ptr.assume_init() };
        let group_sid_ptr = unsafe { group_sid_ptr.assume_init() };
        let dacl_ptr = unsafe { dacl_ptr.assume_init() };
        let sd_ptr = unsafe { sd_ptr.assume_init() };

        Ok(Self {
            owner_sid_ptr,
            group_sid_ptr,
            dacl_ptr,
            sd_ptr,
        })
    }

    pub(super) fn owner(&mut self) -> Owner {
        let owner = match unsafe { lookup_account_sid(self.owner_sid_ptr) } {
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

        let group = match unsafe { lookup_account_sid(self.group_sid_ptr) } {
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

        Owner::new(owner, group)
    }

    pub(super) fn permissions(&mut self) -> io::Result<Permissions> {
        use windows::Win32::Storage::FileSystem::{
            FILE_ACCESS_FLAGS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };

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

        // Assumptions:
        // - xxxxx_sid_ptr are valid pointers to SIDs
        // - xxxxx_trustee is only valid as long as its SID pointer is
        let owner_trustee = unsafe { trustee_from_sid(self.owner_sid_ptr) };
        let group_trustee = unsafe { trustee_from_sid(self.group_sid_ptr) };
        let world_trustee = unsafe { trustee_from_sid(world_sid_ptr) };

        // Assumptions:
        // - xxxxx_trustee are still valid (including underlying SID)
        // - dacl_ptr is still valid
        let owner_access_mask = unsafe { get_acl_access_mask(self.dacl_ptr, &owner_trustee) }?;

        let group_access_mask = unsafe { get_acl_access_mask(self.dacl_ptr, &group_trustee) }?;

        let world_access_mask = unsafe { get_acl_access_mask(self.dacl_ptr, &world_trustee) }?;

        let has_bit = |field: u32, bit: FILE_ACCESS_FLAGS| field & bit.0 != 0;
        Ok(Permissions {
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
        })
    }
}

impl Drop for SecurityInfo {
    fn drop(&mut self) {
        unsafe {
            windows::Win32::System::Memory::LocalFree(self.sd_ptr.0 as _);
        }
    }
}

/// Evaluate an ACL for a particular trustee and get its access rights
///
/// Assumptions:
/// - acl_ptr points to a valid ACL data structure
/// - trustee_ptr points to a valid trustee data structure
/// - Both remain valid through the function call (no long-term requirement)
unsafe fn get_acl_access_mask(
    acl_ptr: *const ACL,
    trustee_ptr: *const TRUSTEE_W,
) -> Result<u32, io::Error> {
    let mut access_mask = 0;

    // Assumptions:
    // - All function assumptions
    // - Result is not valid until return value is checked
    let err_code =
        Security::Authorization::GetEffectiveRightsFromAclW(acl_ptr, trustee_ptr, &mut access_mask);

    if err_code.is_ok() {
        Ok(access_mask)
    } else {
        Err(io::Error::from_raw_os_error(err_code.0 as i32))
    }
}

/// Get a trustee buffer from a SID
///
/// Assumption: sid is valid, and the trustee is only valid as long as the SID
/// is
///
/// Note: winapi's TRUSTEE_W looks different from the one in the MS docs because
/// of some unusual pre-processor macros in the original .h file. The winapi
/// version is correct (MS's doc generator messed up)
unsafe fn trustee_from_sid<P: Into<PSID>>(sid_ptr: P) -> TRUSTEE_W {
    let mut trustee = TRUSTEE_W::default();

    Security::Authorization::BuildTrusteeWithSidW(&mut trustee, sid_ptr);

    trustee
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

#[enumflags2::bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileAttributes {
    /// This file is marked to be included in incremental backup operation.
    /// Windows sets this attribute whenever the file is modified, and backup
    /// software should clear it when processing the file during incremental
    /// backup.
    Archive = 32,
    /// The file is compressed.
    Compressed = 2048,
    /// The file is a directory.
    Directory = 16,
    /// The file or directory is encrypted. For a file, this means that all data
    /// in the file is encrypted. For a directory, this means that encryption is
    /// the default for newly created files and directories.
    Encrypted = 16384,
    /// The file is hidden, and thus is not included in an ordinary directory
    /// listing.
    Hidden = 2,
    /// The file will not be indexed by the operating system's content indexing
    /// service.
    NotContentIndexed = 8192,
    /// The file is offline. The data of the file is not immediately available.
    Offline = 4096,
    /// The file is read-only.
    ReadOnly = 1,
    /// The file contains a reparse point, which is a block of user-defined data
    /// associated with a file or a directory.
    ReparsePoint = 1024,
    /// The file is a system file. That is, the file is part of the operating
    /// system or is used exclusively by the operating system.
    System = 4,
    /// The file is temporary. A temporary file contains data that is needed
    /// while an application is executing but is not needed after the
    /// application is finished. File systems try to keep all the data in memory
    /// for quicker access rather than flushing the data back to mass storage. A
    /// temporary file should be deleted by the application as soon as it is no
    /// longer needed.
    Temporary = 256,
}

/// Returns the [FileAttributes] that are set for the given [`Path`]
#[inline]
pub(crate) fn get_path_attributes(path: &Path) -> enumflags2::BitFlags<FileAttributes> {
    let windows_path = buf_from_os(path.as_os_str());
    let file_attributes = unsafe {
        windows::Win32::Storage::FileSystem::GetFileAttributesW(windows::core::PCWSTR(
            windows_path.as_ptr(),
        ))
    };

    enumflags2::BitFlags::from_bits_truncate(file_attributes)
}

#[cfg(test)]
#[inline]
pub(crate) fn set_path_attributes<B>(path: &Path, attributes: B) -> io::Result<()>
where
    B: Into<enumflags2::BitFlags<FileAttributes>>,
{
    let windows_path = buf_from_os(path.as_os_str());
    unsafe {
        windows::Win32::Storage::FileSystem::SetFileAttributesW(
            windows::core::PCWSTR(windows_path.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                attributes.into().bits(),
            ),
        )
    }
    .ok()
    .map_err(Into::into)
}

/// Checks whether the windows [`hidden`] attribute is set for the given
/// [`Path`]
///
/// [`hidden`]: windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN
#[inline]
pub fn is_path_hidden(path: &Path) -> bool {
    get_path_attributes(path).contains(FileAttributes::Hidden)
}

/// Checks whether the windows [`system`] attribute is set for the given
/// [`Path`]
///
/// [`system`]: windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SYSTEM
#[inline]
pub fn is_path_system(path: &Path) -> bool {
    get_path_attributes(path).contains(FileAttributes::System)
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
