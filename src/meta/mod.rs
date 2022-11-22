mod access_control;
mod date;
mod filetype;
mod indicator;
mod inode;
mod links;
#[cfg(windows)]
mod mode;
pub mod name;
mod owner;
mod permissions;
mod size;
mod symlink;

#[cfg(windows)]
mod windows_utils;

pub use self::access_control::AccessControl;
pub use self::date::Date;
pub use self::filetype::FileType;
pub use self::indicator::Indicator;
pub use self::inode::INode;
pub use self::links::Links;
#[cfg(windows)]
pub use self::mode::Mode;
pub use self::name::Name;
pub use self::owner::Owner;
pub use self::permissions::Permissions;
pub use self::size::Size;
pub use self::symlink::SymLink;
pub use crate::icon::Icons;

use crate::flags::{Display, Flags, Layout};
use crate::{print_error, ExitCode};

use std::io::{self, Error, ErrorKind};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Meta {
    pub name: Name,
    pub path: PathBuf,
    pub permissions: Permissions,
    #[cfg(windows)]
    pub mode: Mode,
    pub date: Date,
    pub owner: Owner,
    pub file_type: FileType,
    pub size: Size,
    pub symlink: SymLink,
    pub indicator: Indicator,
    pub inode: INode,
    pub links: Links,
    pub content: Option<Vec<Meta>>,
    pub access_control: AccessControl,
}

impl Meta {
    pub fn recurse_into(
        &self,
        depth: usize,
        flags: &Flags,
    ) -> io::Result<(Option<Vec<Meta>>, ExitCode)> {
        if depth == 0 {
            return Ok((None, ExitCode::OK));
        }

        if flags.display == Display::DirectoryOnly && flags.layout != Layout::Tree {
            return Ok((None, ExitCode::OK));
        }

        match self.file_type {
            FileType::Directory { .. } => (),
            FileType::SymLink { is_dir: true } => {
                if flags.layout == Layout::OneLine {
                    return Ok((None, ExitCode::OK));
                }
            }
            _ => return Ok((None, ExitCode::OK)),
        }

        let entries = match self.path.read_dir() {
            Ok(entries) => entries,
            Err(err) => {
                print_error!("{}: {}.", self.path.display(), err);
                return Ok((None, ExitCode::MinorIssue));
            }
        };

        let mut content: Vec<Meta> = Vec::new();

        if matches!(flags.display, Display::All | Display::SystemProtected)
            && flags.layout != Layout::Tree
        {
            let mut current_meta = self.clone();
            current_meta.name.name = ".".to_owned();

            let mut parent_meta =
                Self::from_path(&self.path.join(Component::ParentDir), flags.dereference.0)?;
            parent_meta.name.name = "..".to_owned();

            content.push(current_meta);
            content.push(parent_meta);
        }

        let mut exit_code = ExitCode::OK;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            let name = path
                .file_name()
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid file name"))?;

            if flags.ignore_globs.0.is_match(name) {
                continue;
            }

            #[cfg(windows)]
            let is_hidden =
                name.to_string_lossy().starts_with('.') || windows_utils::is_path_hidden(&path);
            #[cfg(not(windows))]
            let is_hidden = name.to_string_lossy().starts_with('.');

            #[cfg(windows)]
            let is_system = windows_utils::is_path_system(&path);
            #[cfg(not(windows))]
            let is_system = false;

            match flags.display {
                // show hidden files, but ignore system protected files
                Display::All | Display::AlmostAll if is_system => continue,
                // ignore hidden and system protected files
                Display::VisibleOnly if is_hidden || is_system => continue,
                _ => {}
            }

            let mut entry_meta = match Self::from_path(&path, flags.dereference.0) {
                Ok(res) => res,
                Err(err) => {
                    print_error!("{}: {}.", path.display(), err);
                    exit_code.set_if_greater(ExitCode::MinorIssue);
                    continue;
                }
            };

            // skip files for --tree -d
            if flags.layout == Layout::Tree
                && flags.display == Display::DirectoryOnly
                && !entry.file_type()?.is_dir()
            {
                continue;
            }

            // check dereferencing
            if flags.dereference.0 || !matches!(entry_meta.file_type, FileType::SymLink { .. }) {
                match entry_meta.recurse_into(depth - 1, flags) {
                    Ok((content, rec_exit_code)) => {
                        entry_meta.content = content;
                        exit_code.set_if_greater(rec_exit_code);
                    }
                    Err(err) => {
                        print_error!("{}: {}.", path.display(), err);
                        exit_code.set_if_greater(ExitCode::MinorIssue);
                        continue;
                    }
                };
            }

            content.push(entry_meta);
        }

        Ok((Some(content), exit_code))
    }

    pub fn calculate_total_size(&mut self) {
        if let FileType::Directory { .. } = self.file_type {
            if let Some(metas) = &mut self.content {
                let mut size_accumulated = self.size.get_bytes();
                for x in &mut metas.iter_mut() {
                    x.calculate_total_size();
                    size_accumulated += x.size.get_bytes();
                }
                self.size = Size::new(size_accumulated);
            } else {
                // possibility that 'depth' limited the recursion in 'recurse_into'
                self.size = Size::new(Meta::calculate_total_file_size(&self.path));
            }
        }
    }

    fn calculate_total_file_size(path: &Path) -> u64 {
        let metadata = path.symlink_metadata();
        let metadata = match metadata {
            Ok(meta) => meta,
            Err(err) => {
                print_error!("{}: {}.", path.display(), err);
                return 0;
            }
        };
        let file_type = metadata.file_type();
        if file_type.is_file() {
            metadata.len()
        } else if file_type.is_dir() {
            let mut size = metadata.len();

            let entries = match path.read_dir() {
                Ok(entries) => entries,
                Err(err) => {
                    print_error!("{}: {}.", path.display(), err);
                    return size;
                }
            };
            for entry in entries {
                let path = match entry {
                    Ok(entry) => entry.path(),
                    Err(err) => {
                        print_error!("{}: {}.", path.display(), err);
                        continue;
                    }
                };
                size += Meta::calculate_total_file_size(&path);
            }
            size
        } else {
            0
        }
    }

    pub fn from_path(path: &Path, dereference: bool) -> io::Result<Self> {
        let mut metadata = path.symlink_metadata()?;
        let mut symlink_meta = None;
        if metadata.file_type().is_symlink() {
            match path.metadata() {
                Ok(m) => {
                    if dereference {
                        metadata = m;
                    } else {
                        symlink_meta = Some(m);
                    }
                }
                Err(e) => {
                    // This case, it is definitely a symlink or
                    // path.symlink_metadata would have errored out
                    if dereference {
                        return Err(e);
                    }
                }
            }
        }

        #[cfg(unix)]
        let owner = Owner::from(&metadata);
        #[cfg(unix)]
        let permissions = Permissions::from(&metadata);

        #[cfg(windows)]
        let (owner, permissions) = windows_utils::get_file_data(path)?;

        #[cfg(windows)]
        let mode = Mode::from(path);

        let access_control = AccessControl::for_path(path);

        #[cfg(not(windows))]
        let file_type = FileType::new(&metadata, symlink_meta.as_ref(), &permissions);

        #[cfg(windows)]
        let file_type = FileType::new(&metadata, symlink_meta.as_ref(), path);

        let name = Name::new(path, file_type);
        let inode = INode::from(&metadata);
        let links = Links::from(&metadata);

        Ok(Self {
            inode,
            links,
            path: path.to_path_buf(),
            symlink: SymLink::from(path),
            size: Size::from(&metadata),
            date: Date::from(&metadata),
            indicator: Indicator::from(file_type),
            owner,
            permissions,
            #[cfg(windows)]
            mode,
            name,
            file_type,
            content: None,
            access_control,
        })
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::Meta;

    #[test]
    fn test_from_path_path() {
        let dir = assert_fs::TempDir::new().unwrap();
        let meta = Meta::from_path(dir.path(), false).unwrap();
        assert_eq!(meta.path, dir.path())
    }
}
