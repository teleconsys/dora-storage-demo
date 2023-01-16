use anyhow::{bail, Result};
use s3::{creds::Credentials, Bucket, BucketConfiguration, Region};

use crate::store::Storage;

pub fn setup_minio_local_storage(
    endpoint: String,
    access_key: Option<String>,
    secret_key: Option<String>,
) -> Result<Storage> {
    let bucket_name = "test";
    let region = Region::Custom {
        region: "eu-south-1".to_owned(),
        endpoint: "http://".to_owned() + endpoint.as_str(),
    };
    let credentials = Credentials {
        access_key,
        secret_key,
        security_token: None,
        session_token: None,
        expiration: None,
    };

    let r = tokio::runtime::Runtime::new()?;
    let response = r.block_on(Bucket::create_with_path_style(
        bucket_name,
        region.clone(),
        credentials.clone(),
        BucketConfiguration::public(),
    ))?;
    let mut bucket = response.bucket;
    match response.response_code {
        200 => (),
        409 => bucket = Bucket::new(bucket_name, region, credentials)?,
        _ => bail!("minio can't instantiate a bucket"),
    };
    Ok(Storage::MinioLocal { bucket })
}
