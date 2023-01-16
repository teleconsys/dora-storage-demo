use anyhow::{bail, Result};
use s3::{creds::Credentials, error::S3Error, Bucket, BucketConfiguration, Region};

use crate::store::Storage;

pub fn setup_minio_local_storage(
    endpoint: String,
    access_key: Option<String>,
    secret_key: Option<String>,
) -> Result<Storage> {

    let bucket_name = "dora-node-bucket";
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
        BucketConfiguration::default(),
    ));

    match response {
        Ok(r) => Ok(Storage::MinioLocal { bucket: r.bucket }),
        Err(e) => if let S3Error::Http(409, ..) = e {
            Ok(Storage::MinioLocal {
            bucket: Bucket::new(bucket_name, region, credentials)?,
        })
        } else {
            bail!("{}", e)
        },
    }
}
