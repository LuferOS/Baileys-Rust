use crate::proto::device_props::PlatformType;

pub struct Browsers;

impl Browsers {
    pub fn ubuntu(browser: &str) -> [String; 3] {
        ["Ubuntu".to_string(), browser.to_string(), "22.04.4".to_string()]
    }

    pub fn macos(browser: &str) -> [String; 3] {
        ["Mac OS".to_string(), browser.to_string(), "14.4.1".to_string()]
    }

    pub fn baileys(browser: &str) -> [String; 3] {
        ["Baileys".to_string(), browser.to_string(), "6.5.0".to_string()]
    }

    pub fn windows(browser: &str) -> [String; 3] {
        ["Windows".to_string(), browser.to_string(), "10.0.22631".to_string()]
    }

    pub fn android(browser: &str) -> [String; 3] {
        [browser.to_string(), "Android".to_string(), String::new()]
    }

    pub fn appropriate(browser: &str) -> [String; 3] {
        let os_name = match std::env::consts::OS {
            "macos" => "Mac OS",
            "windows" => "Windows",
            "android" => "Android",
            "freebsd" => "FreeBSD",
            "openbsd" => "OpenBSD",
            "solaris" => "Solaris",
            _ => "Ubuntu",
        };
        [os_name.to_string(), browser.to_string(), String::new()]
    }
}

pub fn get_platform_id(browser: &str) -> String {
    let upper = browser.to_uppercase();
    PlatformType::from_str_name(&upper)
        .map(|pt| (pt as i32).to_string())
        .unwrap_or_else(|| "1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browsers_and_platform_id() {
        let mac = Browsers::macos("Chrome");
        assert_eq!(mac, ["Mac OS", "Chrome", "14.4.1"]);
        assert_eq!(get_platform_id("Chrome"), (PlatformType::Chrome as i32).to_string());
        assert_eq!(get_platform_id("UnknownBrowser"), "1");
    }
}
