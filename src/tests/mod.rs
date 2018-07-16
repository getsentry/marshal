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

macro_rules! assert_eq_dbg {
    ($left:expr, $right:expr) => {{
        let left = &$left;
        let right = &$right;

        assert!(
            left == right,
            "`left == right` in line {}:\n{}\n{}",
            line!(),
            ::difference::Changeset::new("- left", "+ right", "\n"),
            ::difference::Changeset::new(&format!("{:#?}", left), &format!("{:#?}", right), "\n")
        )
    }};
}

mod test_annotated;
mod test_builtinrules;
mod test_chunking;
mod test_common;
mod test_meta;
mod test_processor;
mod test_protocol;
mod test_rules;
mod test_serde_chrono;
