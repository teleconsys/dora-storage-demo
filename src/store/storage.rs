use anyhow::{bail, Result};
use s3::Bucket;

use super::storages::minio::setup_minio_local_storage;

#[derive(Clone)]
pub enum Storage {
    MinioLocal { bucket: Bucket },
}

pub fn new_storage(
    storage: &str,
    access_key: Option<String>,
    secret_key: Option<String>,
    endpoint: Option<String>,
) -> Result<Storage> {
    let storage: Storage = match storage {
        "minio-local" => setup_minio_local_storage(
            endpoint.expect("minio storage needs an endpoint"),
            access_key,
            secret_key,
        )?,
        _ => panic!("{} storage is not supported", storage),
    };
    Ok(storage)
}

impl Storage {
    pub fn put(&self, path: String, content: &[u8]) -> Result<()> {
        let r = tokio::runtime::Runtime::new()?;
        match self {
            Storage::MinioLocal { bucket } => {
                let response_code = r.block_on(bucket.put_object(path, content))?.status_code();
                if response_code != 200 {
                    bail!("could not put object, error: {}", response_code)
                };
                Ok(())
            }
        }
    }

    pub fn get(&self, path: String) -> Result<Vec<u8>> {
        let r = tokio::runtime::Runtime::new()?;
        match self {
            Storage::MinioLocal { bucket } => {
                let response = r.block_on(bucket.get_object(path))?;
                if response.status_code() != 200 {
                    bail!("could not get object, error: {}", response.status_code())
                };
                Ok(response.bytes().to_vec())
            }
        }
    }

    pub fn delete(&self, path: String) -> Result<()> {
        let r = tokio::runtime::Runtime::new()?;
        match self {
            Storage::MinioLocal { bucket } => {
                let response_code = r.block_on(bucket.delete_object(path))?.status_code();
                if response_code != 204 {
                    bail!("could not delete object, error: {}", response_code)
                };
                Ok(())
            }
        }
    }

    pub fn health_check(&self) -> Result<()> {
        match self {
            Storage::MinioLocal { .. } => {
                let test_path = "test.file".to_owned();
                let test_data = b"test_data";
                // PUT test
                self.put(test_path.clone(), test_data)?;

                // GET test
                let data = self.get(test_path.clone())?;
                assert_eq!(data, test_data);

                // DEL test
                self.delete(test_path)?;

                Ok(())
            }
        }
    }
}
