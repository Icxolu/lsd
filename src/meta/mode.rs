use super::windows_utils::{self, FileAttributes};
use crate::color::{ColoredString, Colors, Elem};
use crate::flags::Flags;
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Mode(enumflags2::BitFlags<FileAttributes>);

impl From<&Path> for Mode {
    fn from(path: &Path) -> Self {
        Self(windows_utils::get_path_attributes(path))
    }
}

impl Mode {
    pub fn render(&self, colors: &Colors, _flags: &Flags) -> ColoredString {
        let bit = |flag, chr: &'static str, elem: &Elem| {
            if self.0.contains(flag) {
                colors.colorize(chr, elem)
            } else {
                colors.colorize('-', &Elem::NoAccess)
            }
        };

        let res = [
            bit(FileAttributes::Archive, "a", &Elem::Archive),
            bit(FileAttributes::ReadOnly, "r", &Elem::ReadOnly),
            bit(FileAttributes::Compressed, "c", &Elem::Compressed),
            bit(FileAttributes::Encrypted, "e", &Elem::Encrypted),
            bit(FileAttributes::Temporary, "t", &Elem::Temporary),
            bit(
                FileAttributes::NotContentIndexed,
                "n",
                &Elem::NotContentIndexed,
            ),
            bit(FileAttributes::Hidden, "h", &Elem::Hidden),
            bit(FileAttributes::System, "s", &Elem::System),
            bit(FileAttributes::Offline, "o", &Elem::Offline),
        ]
        .into_iter()
        // From the experiment, the maximum string size is 153 bytes
        .fold(String::with_capacity(160), |mut acc, x| {
            acc.push_str(&x.to_string());
            acc
        });

        ColoredString::new(Colors::default_style(), res)
    }
}

#[cfg(test)]
mod test {
    use super::{windows_utils::set_path_attributes, FileAttributes, Flags, Mode};
    use crate::color::{Colors, ThemeOption};
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn mode() {
        let tmp_dir = tempdir().expect("failed to create temp dir");

        // Create the file;
        let file_path = tmp_dir.path().join("file.txt");
        File::create(&file_path).expect("failed to create file");
        set_path_attributes(
            &file_path,
            FileAttributes::Hidden | FileAttributes::Temporary,
        )
        .expect("unable to set file attributes to file");

        let colors = Colors::new(ThemeOption::NoColor);
        let perms = Mode::from(file_path.as_ref());

        assert_eq!(
            "----t-h--",
            perms.render(&colors, &Flags::default()).content()
        );
    }
}
