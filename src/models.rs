use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseAttachmentResult {
    pub results: Vec<ResponseAttachment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseAttachment {
    pub id: String,
    pub title: String,
    pub metadata: ResponseAttachmentMetadata,
    #[serde(rename = "_links")]
    pub links: ResponseAttachmentLinks,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResponseAttachmentMetadata {
    pub media_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseAttachmentLinks {
    pub download: String,
}

#[derive(Debug)]
pub struct Attachment {
    pub id: String,
    pub title: String,
    pub media_type: String,
    pub download_link: String,
}
