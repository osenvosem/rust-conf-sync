use std::{
    collections::HashSet,
    fs::ReadDir,
    path::{Path, PathBuf},
};

use dotenvy::dotenv;

use crate::models::Attachment;

pub fn clean_url(url: &str) -> String {
    url.splitn(2, "://")
        .map(|s| {
            s.split("/")
                .filter(|p| !p.is_empty())
                .collect::<Vec<&str>>()
                .join("/")
        })
        .collect::<Vec<String>>()
        .join("://")
}

pub fn get_path_filename(file_path: &PathBuf) -> (String, String) {
    let string_path = file_path.to_string_lossy().to_string();
    let filename = Path::new(&string_path)
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap();

    (string_path, filename)
}

pub fn get_local_filenames(paths: ReadDir, ignore_files: &Vec<&str>) -> Vec<String> {
    paths
        .filter(|p| p.as_ref().unwrap().path().is_file())
        .map(|f| {
            f.unwrap()
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .filter(|f| !ignore_files.iter().any(|pat| f.contains(pat)))
        .collect::<Vec<String>>()
}

pub fn calc_file_difference(
    attachments: &Vec<Attachment>,
    local_files: &Vec<String>,
) -> (bool, Vec<String>, Vec<String>) {
    let up_set: HashSet<_> = attachments
        .into_iter()
        .map(|a| a.title.clone())
        .to_owned()
        .collect();

    let down_set: HashSet<_> = local_files
        .into_iter()
        .map(|b| b.to_owned())
        .to_owned()
        .collect();

    let up_diff: Vec<_> = (&up_set - &down_set).into_iter().collect();
    let down_diff: Vec<_> = (&down_set - &up_set).into_iter().collect();

    (
        !up_diff.is_empty() || !down_diff.is_empty(),
        up_diff,
        down_diff,
    )
}
