#![allow(unused)]

mod constants;
mod helpers;
mod models;

use anyhow;
use dotenvy::dotenv;
use env_logger;
use helpers::get_local_filenames;
use log;
use models::{Attachment, ResponseAttachmentResult};
use notify::{self, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use reqwest::{self, header::HeaderMap, Url};
use shellexpand;
use std::{
    env, fs,
    io::{Cursor, Read},
    path::{Path, MAIN_SEPARATOR_STR},
    sync::{self, Arc},
    thread,
    time::Duration,
};

use crate::helpers::calc_file_difference;

fn main() -> anyhow::Result<()> {
    match dotenv() {
        Ok(path) => {
            println!("Env vars are loaded from {}", path.to_string_lossy());
        }
        Err(_) => {
            println!("Env vars are loaded from the environment");
        }
    };

    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, "rust_conf_sync=debug"),
    );

    let client = reqwest::blocking::Client::new();

    // Env vars resolving
    let username = dotenvy::var("CONF_USERNAME").expect("Please provide CONF_USERNAME env var");
    let password = dotenvy::var("CONF_PASSWORD").expect("Please provide CONF_PASSWORD env var");
    let sync_dir = dotenvy::var("CONF_SYNC_DIR").expect("Please provide CONF_SYNC_DIR env var");
    let conf_host = dotenvy::var("CONF_HOST").expect("Please provide CONF_HOST env var");
    let ignore_files_env = dotenvy::var("CONF_IGNORE_FILES");
    let sync_dir = shellexpand::tilde(&sync_dir).to_string();
    let page_url = if let Ok(env_page_url) = dotenvy::var("CONF_PAGE_URL") {
        let normalized_url = helpers::clean_url(env_page_url.as_str());
        if normalized_url.contains(conf_host.as_str()) {
            normalized_url
        } else {
            helpers::clean_url(format!("{conf_host}/{normalized_url}").as_str())
        }
    } else {
        format!("{conf_host}/display/~{username}/Files")
    };
    let poll_interval = if let Ok(val) = dotenvy::var("CONF_POLL_INTERVAL") {
        if let Ok(parsed) = val.parse() {
            parsed
        } else {
            10
        }
    } else {
        10
    };

    let page_id = get_page_id(&client, &username, &password, &page_url);
    let base_api_url = helpers::clean_url(format!("{conf_host}/rest/api/content").as_str());
    let common_api_url = format!("{base_api_url}/{page_id}/child/attachment");

    let mut ignore_files_vec = ".sb-,.DS_Store,$".split(",").collect::<Vec<&str>>();
    if let Ok(ref ifs) = ignore_files_env {
        ifs.split(",").for_each(|elem| {
            if !ignore_files_vec.contains(&elem) {
                ignore_files_vec.push(elem);
            }
        });
    }

    fs::create_dir_all(&sync_dir).expect("Could not create sync dir");

    initial_sync(
        client.clone(),
        username.clone(),
        password.clone(),
        common_api_url.clone(),
        ignore_files_vec
            .clone()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sync_dir.clone(),
    );

    let (tx, rx) = sync::mpsc::channel();
    let (block_tx, block_rx) = sync::mpsc::channel::<bool>();

    start_polling_thread(
        block_tx,
        client.clone(),
        username.clone(),
        password.clone(),
        common_api_url.clone(),
        ignore_files_vec
            .clone()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sync_dir.clone(),
        poll_interval,
    );

    let mut watcher =
        RecommendedWatcher::new(tx, notify::Config::default()).expect("Error creating watcher");

    watcher
        .watch(Path::new(&sync_dir), RecursiveMode::Recursive)
        .expect("Error starting watcher");

    let mut watcher_blocked = false;

    for res in rx {
        if let Ok(block) = block_rx.try_recv() {
            watcher_blocked = block;
        }

        if watcher_blocked {
            log::debug!("Watcher blocked");
            continue;
        } else {
            log::debug!("Watcher released");
        }

        if let Ok(event) = &res {
            log::debug!("{:?} {:?}", event.kind, event.paths.get(0).unwrap());

            let (_, filename) = helpers::get_path_filename(event.paths.get(0).unwrap());

            if ignore_files_vec.iter().any(|elem| filename.contains(*elem)) {
                // log::debug!("file ignored {}", &filename);

                continue;
            }
        }

        match res {
            Ok(event) => match event.kind {
                notify::EventKind::Create(create_kind) => match create_kind {
                    notify::event::CreateKind::File => {
                        let (file_path, _) =
                            helpers::get_path_filename(event.paths.get(0).unwrap());

                        upload_file(&client, &username, &password, &common_api_url, &file_path)
                            .expect("Failed upload file");
                    }
                    _ => {}
                },
                notify::EventKind::Modify(modify_kind) => match modify_kind {
                    notify::event::ModifyKind::Name(_) => {
                        let attachments =
                            get_attachment_list(&client, &username, &password, &common_api_url)
                                .unwrap();

                        let local_files = helpers::get_local_filenames(
                            fs::read_dir(&sync_dir).expect("Error reading local files"),
                            &ignore_files_vec,
                        );

                        let (file_path, filename) =
                            helpers::get_path_filename(&event.paths.get(0).unwrap());

                        let (is_there_diff, _, _) =
                            helpers::calc_file_difference(&attachments, &local_files);
                        if is_there_diff {
                            let uploaded_file = attachments.iter().find(|a| a.title.eq(&filename));

                            if let Some(uf) = uploaded_file {
                                delete_file(&client, &username, &password, &base_api_url, &uf.id)?;
                            } else {
                                upload_file(
                                    &client,
                                    &username,
                                    &password,
                                    &common_api_url,
                                    &file_path,
                                )?;
                            }
                        } else {
                            let attachment = attachments.iter().find(|att| att.title == filename);
                            if let Some(att) = attachment {
                                update_file(
                                    &client,
                                    &username,
                                    &password,
                                    &common_api_url,
                                    &file_path,
                                    &att.id,
                                )?;
                            }
                        }
                    }
                    _ => {}
                },
                notify::EventKind::Remove(remove_kind) => match remove_kind {
                    notify::event::RemoveKind::File => {
                        let attachments =
                            get_attachment_list(&client, &username, &password, &common_api_url)
                                .unwrap();
                        let (_, filename) = helpers::get_path_filename(event.paths.get(0).unwrap());
                        match attachments.iter().find(|a| a.title == filename) {
                            Some(remote_att) => {
                                delete_file(
                                    &client,
                                    &username,
                                    &password,
                                    &base_api_url,
                                    &remote_att.id,
                                )?;
                            }
                            None => {}
                        }
                    }
                    _ => {}
                },

                _ => {}
            },
            Err(error) => println!("Error: {error:?}"),
        }
    }

    Ok(())
}

fn get_page_id(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    url: &String,
) -> String {
    let page_id_re = Regex::new(constants::PAGE_ID_RE).unwrap();

    let html_response = client
        .get(url)
        .basic_auth(username, Some(password))
        .send()
        .unwrap()
        .text()
        .unwrap();

    let caps = page_id_re
        .captures(&html_response)
        .expect("Cannot extract page id from HTML response");

    log::debug!("get_page_id");

    caps.name("page_id")
        .expect("Cannot get page id")
        .as_str()
        .to_string()
}

fn get_attachment_list(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    url: &String,
) -> anyhow::Result<Vec<Attachment>> {
    let res = client
        .get(url)
        .basic_auth(username, Some(password))
        .send()
        .expect("attachments request error")
        .json::<ResponseAttachmentResult>()
        .expect("Error parse attachment list");

    let attachments = res
        .results
        .iter()
        .map(|ra| Attachment {
            id: ra.id.to_owned(),
            title: ra.title.to_owned(),
            media_type: ra.metadata.media_type.to_owned(),
            download_link: ra.links.download.to_owned(),
        })
        .collect();

    log::debug!("get_attachment_list");

    Ok(attachments)
}

fn upload_file(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    url: &String,
    file_path: &String,
) -> anyhow::Result<()> {
    let file = fs::read(file_path.clone())?;
    let filename = Path::new(file_path.as_str()).file_name().unwrap();

    let mut headers: HeaderMap = HeaderMap::new();
    headers.insert("X-Atlassian-Token", "nocheck".parse()?);

    let form = reqwest::blocking::multipart::Form::new()
        .text("recource_name", filename.to_string_lossy().to_string())
        .part(
            "file",
            reqwest::blocking::multipart::Part::bytes(file)
                .file_name(filename.to_string_lossy().to_string()),
        );

    client
        .post(url)
        .basic_auth(&username, Some(password))
        .headers(headers)
        .multipart(form)
        .send()
        .expect("Error upload file");

    log::debug!("upload_file");

    Ok(())
}

fn update_file(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    api_url: &String,
    file_path: &String,
    attachment_id: &String,
) -> anyhow::Result<()> {
    let url = format!("{api_url}/att{attachment_id}/data");
    let file = fs::read(file_path.clone())?;
    let filename = Path::new(file_path.as_str()).file_name().unwrap();

    let mut headers: HeaderMap = HeaderMap::new();
    headers.insert("X-Atlassian-Token", "nocheck".parse()?);

    let form = reqwest::blocking::multipart::Form::new()
        .text("recource_name", filename.to_string_lossy().to_string())
        .part(
            "file",
            reqwest::blocking::multipart::Part::bytes(file)
                .file_name(filename.to_string_lossy().to_string()),
        );

    client
        .post(url)
        .basic_auth(&username, Some(password))
        .headers(headers)
        .multipart(form)
        .send()?;

    log::debug!("update_file");

    Ok(())
}

fn delete_file(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    api_url: &String,
    attachment_id: &String,
) -> anyhow::Result<()> {
    let url = format!("{api_url}/{attachment_id}?status=current");

    let mut headers: HeaderMap = HeaderMap::new();
    headers.insert("X-Atlassian-Token", "nocheck".parse()?);

    client
        .delete(url)
        .basic_auth(&username, Some(password))
        .headers(headers)
        .send()
        .expect("Error delete file");

    log::debug!("delete_file");

    Ok(())
}

fn initial_sync(
    client: reqwest::blocking::Client,
    username: String,
    password: String,
    url: String,
    ignore_files: Vec<String>,
    sync_dir: String,
) -> anyhow::Result<()> {
    let attachments = get_attachment_list(&client, &username, &password, &url).unwrap();

    let dir_contents = fs::read_dir(&sync_dir).expect("Error reading local files");

    let local_files = get_local_filenames(
        dir_contents,
        &ignore_files.iter().map(|s| s.as_str()).collect(),
    );

    let (_, up_diff, down_diff) = calc_file_difference(&attachments, &local_files);

    if !up_diff.is_empty() {
        let scheme = Url::parse(&url).unwrap().scheme().to_string();
        let domain = Url::parse(&url).unwrap().host().unwrap().to_string();

        up_diff.iter().for_each(|file_name| {
            let Attachment {
                download_link,
                title,
                ..
            } = attachments
                .iter()
                .find(|att| att.title.contains(file_name))
                .unwrap();
            let download_url = format!("{scheme}://{domain}{download_link}");

            download_file(
                &client,
                &username,
                &password,
                &download_url,
                &title,
                &sync_dir,
            );
            ()
        });
        thread::sleep(Duration::from_millis(500));
    }

    if !down_diff.is_empty() {
        let dir_contents = fs::read_dir(&sync_dir).expect("Error reading local files");
        let down_diff_paths = dir_contents
            .map(|p| p.unwrap().path().to_string_lossy().to_string())
            .filter(|res| down_diff.iter().any(|pat| res.contains(pat)))
            .collect::<Vec<String>>();

        down_diff_paths.iter().for_each(|file_path| {
            upload_file(&client, &username, &password, &url, file_path);
            ()
        });
    }

    log::debug!("Initial sync");
    Ok(())
}

fn download_file(
    client: &reqwest::blocking::Client,
    username: &String,
    password: &String,
    file_download_url: &String,
    file_name: &String,
    sync_dir: &String,
) -> anyhow::Result<()> {
    let res = client
        .get(file_download_url)
        .send()
        .expect("Error download file");
    let file_local_path = format!("{sync_dir}{MAIN_SEPARATOR_STR}{file_name}");
    let mut file = fs::File::create(file_local_path).unwrap();
    let mut content = Cursor::new(res.bytes().expect("Error get downloaded file contents"));
    std::io::copy(&mut content, &mut file);

    log::debug!("Download file");
    Ok(())
}

fn start_polling_thread(
    tx: sync::mpsc::Sender<bool>,
    client: reqwest::blocking::Client,
    username: String,
    password: String,
    url: String,
    ignore_files: Vec<String>,
    sync_dir: String,
    poll_interval: u64,
) {
    thread::spawn(move || loop {
        let attachments = get_attachment_list(&client, &username, &password, &url).unwrap();

        let dir_contents = fs::read_dir(&sync_dir).expect("Error reading local files");

        let local_files = get_local_filenames(
            dir_contents,
            &ignore_files.iter().map(|s| s.as_str()).collect(),
        );

        let (_, up_diff, down_diff) = calc_file_difference(&attachments, &local_files);

        if !up_diff.is_empty() {
            let scheme = Url::parse(&url).unwrap().scheme().to_string();
            let domain = Url::parse(&url).unwrap().host().unwrap().to_string();

            tx.send(true).unwrap();
            up_diff.iter().for_each(|file_name| {
                let Attachment {
                    download_link,
                    title,
                    ..
                } = attachments
                    .iter()
                    .find(|att| att.title.contains(file_name))
                    .unwrap();
                let download_url = format!("{scheme}://{domain}{download_link}");

                download_file(
                    &client,
                    &username,
                    &password,
                    &download_url,
                    &title,
                    &sync_dir,
                );
                ()
            });
            thread::sleep(Duration::from_millis(500));
            tx.send(false).unwrap();
        }

        if !down_diff.is_empty() {
            let dir_contents = fs::read_dir(&sync_dir).expect("Error reading local files");
            let down_diff_paths = dir_contents
                .map(|p| p.unwrap().path().to_string_lossy().to_string())
                .filter(|res| down_diff.iter().any(|pat| res.contains(pat)))
                .collect::<Vec<String>>();

            tx.send(true).unwrap();
            down_diff_paths.iter().for_each(|file_path| {
                match fs::remove_file(&file_path) {
                    Ok(_) => log::debug!("File removed {}", file_path),
                    Err(err) => log::error!("{err}:?"),
                }
                ()
            });
            thread::sleep(Duration::from_millis(500));
            tx.send(false).unwrap();
        }

        thread::sleep(Duration::from_secs(poll_interval));
    });
}
