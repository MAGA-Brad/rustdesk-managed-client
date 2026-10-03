use hbb_common::{anyhow::anyhow, ResultType};
use std::{
    ptr::{null, null_mut},
    slice,
};
use winapi::um::{
    dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN},
    winbase::LocalFree,
    wincrypt::DATA_BLOB,
};

struct ProtectedBlob(DATA_BLOB);

impl Drop for ProtectedBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                let _ = LocalFree(self.0.pbData.cast());
            }
            self.0.pbData = null_mut();
            self.0.cbData = 0;
        }
    }
}

fn input_blob(data: &[u8]) -> ResultType<DATA_BLOB> {
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow!("DPAPI input is too large"))?;

    Ok(DATA_BLOB {
        cbData: length,
        pbData: data.as_ptr() as *mut u8,
    })
}

pub(crate) fn protect_machine_scope(data: &[u8]) -> ResultType<Vec<u8>> {
    if data.is_empty() {
        return Err(anyhow!("DPAPI cannot protect an empty value"));
    }

    let mut input = input_blob(data)?;
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let succeeded = unsafe {
        CryptProtectData(
            &mut input,
            null(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if succeeded == 0 {
        return Err(anyhow!(
            "CryptProtectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let output = ProtectedBlob(output);

    if output.0.pbData.is_null() || output.0.cbData == 0 {
        return Err(anyhow!("CryptProtectData returned no protected data"));
    }

    Ok(unsafe {
        slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
    })
}

pub(crate) fn unprotect_machine_scope(data: &[u8]) -> ResultType<Vec<u8>> {
    if data.is_empty() {
        return Err(anyhow!("DPAPI cannot unprotect an empty value"));
    }

    let mut input = input_blob(data)?;
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let succeeded = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if succeeded == 0 {
        return Err(anyhow!(
            "CryptUnprotectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let output = ProtectedBlob(output);

    if output.0.pbData.is_null() || output.0.cbData == 0 {
        return Err(anyhow!("CryptUnprotectData returned no plaintext data"));
    }

    Ok(unsafe {
        slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_scope_round_trip() {
        let plaintext = b"rustdesk-directory-dpapi-test";
        let protected = protect_machine_scope(plaintext).unwrap();

        assert_ne!(protected, plaintext);
        assert_eq!(unprotect_machine_scope(&protected).unwrap(), plaintext);
    }
}
