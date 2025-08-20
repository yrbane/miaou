// Module mobile - Spécifique aux plateformes mobiles
// Fonctionnalités communes Android et iOS

use crate::PlatformInterface;

/// Plateforme mobile (Android/iOS)
pub struct MobilePlatform {
    initialized: bool,
    platform_name: &'static str,
}

impl MobilePlatform {
    /// Crée une nouvelle plateforme mobile
    #[must_use]
    pub const fn new(platform_name: &'static str) -> Self {
        Self {
            initialized: false,
            platform_name,
        }
    }
}

impl PlatformInterface for MobilePlatform {
    fn initialize(&mut self) -> Result<(), String> {
        if !self.initialized {
            self.initialized = true;
            println!("Initialisation mobile pour {}", self.platform_name);
        }
        Ok(())
    }

    fn get_platform_name(&self) -> &'static str {
        self.platform_name
    }
}

// Interface Android via JNI
#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use jni::objects::JClass;
    use jni::sys::jstring;
    use jni::JNIEnv;

    #[no_mangle]
    pub extern "system" fn Java_net_nethttp_miaou_MiaouLib_hello(
        mut env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let output = env
            .new_string("Miaou Android")
            .expect("Impossible de créer une string Java");
        output.into_raw()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_nethttp_miaou_MiaouLib_initialize(
        _env: JNIEnv,
        _class: JClass,
    ) {
        let mut platform = MobilePlatform::new("Android");
        let _ = platform.initialize();
    }
}

// Interface iOS via Objective-C
#[cfg(target_os = "ios")]
pub mod ios {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    #[no_mangle]
    pub extern "C" fn miaou_hello() -> *const c_char {
        let hello = CString::new("Miaou iOS").unwrap();
        hello.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn miaou_initialize() {
        let mut platform = MobilePlatform::new("iOS");
        let _ = platform.initialize();
    }

    #[no_mangle]
    pub extern "C" fn miaou_free_string(ptr: *mut c_char) {
        if !ptr.is_null() {
            unsafe {
                CString::from_raw(ptr);
            }
        }
    }
}
