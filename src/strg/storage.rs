use anyhow::Result;
use s3::{creds::Credentials, Bucket, BucketConfiguration, Region};

pub fn test_storage(endpoint: String) -> Result<()> {
    let bucket_name = "test";
    let region = "eu-south-1";

    let r = tokio::runtime::Runtime::new()?;
    let response = r.block_on(Bucket::create_with_path_style(
        bucket_name,
        Region::Custom {
            region: region.to_owned(),
            endpoint: endpoint.to_owned(),
        },
        Credentials {
            access_key: Some("admin".to_owned()),
            secret_key: Some("password".to_owned()),
            security_token: None,
            session_token: None,
            expiration: None,
        },
        BucketConfiguration::default(),
    ))?;
    assert!(response.success());
    let bucket = Bucket::new(
        bucket_name,
        Region::Custom {
            region: region.to_owned(),
            endpoint,
        },
        Credentials {
            access_key: Some("admin".to_owned()),
            secret_key: Some("password".to_owned()),
            security_token: None,
            session_token: None,
            expiration: None,
        },
    )?
    .with_path_style();

    let s3_path = "test.file";
    let test = b"I'm going to S3!";
    let response = r.block_on(bucket.put_object(s3_path, test))?;
    assert_eq!(response.status_code(), 200);

    let response = r.block_on(bucket.get_object(s3_path))?;
    assert_eq!(response.status_code(), 200);
    assert_eq!(test, response.bytes());

    let response = r.block_on(bucket.get_object_range(s3_path, 100, Some(1000)))?;
    assert_eq!(response.status_code(), 206);

    let (head_object_result, code) = r.block_on(bucket.head_object(s3_path))?;
    assert_eq!(code, 200);
    assert_eq!(
        head_object_result.content_type.unwrap_or_default(),
        "application/octet-stream".to_owned()
    );

    let response = r.block_on(bucket.delete_object(s3_path))?;
    assert_eq!(response.status_code(), 204);

    Ok(())
}
