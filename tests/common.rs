use std::fs;
use std::path::Path;

pub fn read_fixture<P: AsRef<Path>>(path: P) -> String {
    let full_path = Path::new("tests/").join(path.as_ref());
    let mut string = fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("failed to read fixture '{:?}': {:?}", full_path, e));

    if string.ends_with('\n') {
        let len = string.len();
        string.truncate(len - 1);
    }

    string
}

// XXX: Copy/paste from testutils.rs
#[macro_export]
macro_rules! assert_eq_str {
    ($left:expr, $right:expr) => {{
        let left = &($left);
        let right = &$right;

        assert!(
            left == right,
            "`left == right` in line {}:\n{}\n{}",
            line!(),
            ::difference::Changeset::new("- left", "+ right", "\n"),
            ::difference::Changeset::new(&left, &right, "\n")
        )
    }};
}
