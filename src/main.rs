use std::fs::File;
use std::io::{self, Read};
use flate2::read::DeflateDecoder;
use aws_sdk_s3::Client ;
use std::error::Error;
use aws_sdk_s3::config::Region;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};


struct ZipFileEntry {
    file_name: String,
    file_offset: u64,
    compressed_size: u32,
   // uncompressed_size: u32,
    compression_method: u16,
}

async fn download_bytes(
    client: &Client,
    bucket_name: &str,
    object_key: &str,
    byte_range: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let resp = client
        .get_object()
        .bucket(bucket_name)
        .key(object_key)
        .range(byte_range)
        .send()
        .await?;

    let body = resp.body.collect().await?;
    Ok(body.to_vec())
}


fn find_eocd_offset(buffer: &Vec<u8>) -> u64 {
    const EOCD_SIGNATURE: &[u8; 4] = b"\x50\x4b\x05\x06";

    for i in (0..buffer.len() - 4).rev() {
        if &buffer[i..i + 4] == EOCD_SIGNATURE {
            return i as u64;
        }
    }
    0
}

fn read_central_directory_offset(buffer: &Vec<u8>, eocd_offset: u64) -> u64 {
    let offset_buffer: [u8; 4] = buffer[eocd_offset as usize + 16..eocd_offset as usize + 20].try_into().expect("Invalid slice size");
    u32::from_le_bytes(offset_buffer) as u64
}

fn read_central_directory_entry(
    buffer: &Vec<u8>,
    target_file: String,
) -> Option<ZipFileEntry> {
    const CENTRAL_FILE_HEADER_SIGNATURE: &[u8; 4] = b"\x50\x4b\x01\x02"; // Central File Header signature
    let mut start = 0;

    while start + 46 <= buffer.len() {
        // Check for Central File Header signature
        if &buffer[start..start + 4] != CENTRAL_FILE_HEADER_SIGNATURE {
            break;
        }

        // Read 46-byte central directory file header
        let header = &buffer[start..start + 46];

        // Get lengths from the header
        let file_name_length = u16::from_le_bytes([header[28], header[29]]) as usize;
        let extra_field_length = u16::from_le_bytes([header[30], header[31]]) as usize;
        let file_comment_length = u16::from_le_bytes([header[32], header[33]]) as usize;

        // Get the compressed and uncompressed sizes
        let compressed_size = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
     //   let uncompressed_size = u32::from_le_bytes([header[24], header[25], header[26], header[27]]);
        let compression_method = u16::from_le_bytes([header[10], header[11]]);
        let local_file_header_offset = u32::from_le_bytes([header[42], header[43], header[44], header[45]]) as u64;

        // Extract the file name
        let file_name_start = start + 46;
        if file_name_start + file_name_length > buffer.len() {
            break; // Prevent buffer overrun
        }

        let file_name_bytes = &buffer[file_name_start..file_name_start + file_name_length];
        let file_name = String::from_utf8_lossy(file_name_bytes);

        if file_name == target_file {
            println!("Found File: {} !!!!!!!!" , file_name);
            return Some(ZipFileEntry {
                file_name: file_name.into(),
                file_offset: local_file_header_offset,
                compressed_size,
                //uncompressed_size,
                compression_method,
            });
        }

        // Advance to the next file entry in the central directory
        start += 46 + file_name_length + extra_field_length + file_comment_length;
    }
    None
}

fn get_file_offset(buffer: &Vec<u8>, entry: &ZipFileEntry) -> u64 {
    let file_name_length = u16::from_le_bytes([buffer[26], buffer[27]]) as usize;
    let extra_field_length = u16::from_le_bytes([buffer[28], buffer[29]]) as usize;
    entry.file_offset + 30 + file_name_length as u64 + extra_field_length as u64
}

fn extract_file(file: &Vec<u8>, entry: &ZipFileEntry, output_dir: &str) -> io::Result<()> {
    let output_path = std::path::Path::new(output_dir).join(&entry.file_name);
    std::fs::create_dir_all(output_path.parent().unwrap())?;
    let mut output_file = File::create(output_path)?;

    match entry.compression_method {
        0 => {
            // No compression
            io::copy(&mut &file[..], &mut output_file)?;  // Dereference file to mutable slice
        }
        8 => {
            let mut compressed_data = file.take(entry.compressed_size as u64);
            let mut decoder = DeflateDecoder::new(&mut compressed_data);
            io::copy(&mut decoder, &mut output_file)?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "Unsupported compression method")),
    }

    Ok(())
}

#[tokio::main]
async fn main()  {

// ================================================================================
// ================================================================================
    let target_file_name = "test/RRIF0045_147-2023_F1_140723_062728.JPG";
    let output_dir = "output";

    let bucket_name = "flyghtcloud";
    let obj_key = "test.zip";
// ================================================================================
// ================================================================================

    let s3_endpoint: Option<String> = Some("http://127.0.0.1:9000".to_string());
    let region_provider =
        RegionProviderChain::default_provider().or_else(Region::new("asia-south-1"));
    let shared_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(region_provider)
        .load()
        .await;

    let s3_config = if let Some(s3_endpoint) = s3_endpoint {
        aws_sdk_s3::config::Builder::from(&shared_config)
            .endpoint_url(s3_endpoint)
            .force_path_style(true)
            .build()
    } else {
        aws_sdk_s3::config::Builder::from(&shared_config).build()
    };
    let client = aws_sdk_s3::Client::from_conf(s3_config);


    let head_resp = client
        .head_object()
        .bucket(bucket_name)
        .key(obj_key)
        .send()
        .await.unwrap();

    // Get the total size of the object
    let file_size = match head_resp.content_length() {
        Some(length) => length as usize,
        None => panic!("Not found"), // Correct error handling
    };

    // Calculate the byte range for the last 64 KB
    let start_byte = if file_size > 65536 { file_size - 65536 } else { 0 };
    let end_byte = file_size - 1;
    let byte_range = format!("bytes={}-{}", start_byte, end_byte);
    println!("Byte Range: {}", byte_range);

    let buffer = download_bytes(&client, bucket_name, obj_key, &byte_range).await.unwrap();
    println!("Buffer len: {}", buffer.len());

    let offset = find_eocd_offset(&buffer);
    println!("EOCD offset: {:?}", offset);

    let central_dir_offset = read_central_directory_offset(&buffer, offset);
    println!("Central dir offset: {:?}", central_dir_offset);

    let byte_range = format!("bytes={}-{}", central_dir_offset as usize, end_byte);
    let buffer = download_bytes(&client, bucket_name, obj_key, &byte_range).await.unwrap();

    let file_entity = read_central_directory_entry(&buffer, target_file_name.to_string()).unwrap();

    let byte_range = format!("bytes={}-{}", file_entity.file_offset as usize, file_entity.file_offset as usize + 30);
    let buffer = download_bytes(&client, bucket_name, obj_key, &byte_range).await.unwrap();
    let file_offset = get_file_offset(&buffer, &file_entity);

    let byte_range = format!("bytes={}-{}", file_offset as usize, file_offset as u32 + file_entity.compressed_size);
    let buffer = download_bytes(&client, bucket_name, obj_key, &byte_range).await.unwrap();
    extract_file(&buffer, &file_entity, output_dir).unwrap();
}

