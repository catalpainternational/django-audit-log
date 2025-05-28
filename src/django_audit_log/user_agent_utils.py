import re


class UserAgentUtil:
    """Utility class for parsing and normalizing user agents."""

    # Samsung device model mapping
    SAMSUNG_DEVICE_MODELS = {
        "gta4ljt": "Galaxy Tab A4 Lite",
        "gta8xx": "Galaxy Tab A8",
        "gta9pxxx": "Galaxy Tab A9+",
        "gtanotexlltedx": "Galaxy Note 10.1",
        "gtaxlltexx": "Galaxy Tab A 10.1",
        "gts210ltedx": "Galaxy Tab S2 9.7 LTE",
        "gts210ltexx": "Galaxy Tab S2 9.7 LTE",
    }

    # Browser pattern regex
    BROWSER_PATTERNS = [
        (
            r"tl\.eskola\.eskola_app-(\d+\.\d+\.\d+)-release(?:/(\w+))?",
            "Eskola APK",
        ),  # Non-playstore format
        (
            r"tl\.eskola\.eskola_app\.playstore-(\d+\.\d+\.\d+)-release(?:/(\w+))?",
            "Eskola APK",
        ),  # Playstore format
        (r"Chrome/(\d+)", "Chrome"),
        (r"Firefox/(\d+)", "Firefox"),
        (r"Safari/(\d+)", "Safari"),
        (r"Edge/(\d+)", "Edge"),
        (r"Edg/(\d+)", "Edge"),  # New Edge based on Chromium
        (r"MSIE\s(\d+)", "Internet Explorer"),
        (r"Trident/.*rv:(\d+)", "Internet Explorer"),
        (r"OPR/(\d+)", "Opera"),
        (r"Opera/(\d+)", "Opera"),
        (r"UCBrowser/(\d+)", "UC Browser"),
        (r"SamsungBrowser/(\d+)", "Samsung Browser"),
        (r"YaBrowser/(\d+)", "Yandex Browser"),
        (r"HeadlessChrome", "Headless Chrome"),
        (r"Googlebot", "Googlebot"),
        (r"bingbot", "Bingbot"),
        (r"DuckDuckBot", "DuckDuckBot"),
        (r"Dalvik/(\d+)", "Dalvik"),  # Android Runtime Environment
    ]

    # OS pattern regex
    OS_PATTERNS = [
        (r"Windows NT 10\.0", "Windows 10"),
        (r"Windows NT 6\.3", "Windows 8.1"),
        (r"Windows NT 6\.2", "Windows 8"),
        (r"Windows NT 6\.1", "Windows 7"),
        (r"Windows NT 6\.0", "Windows Vista"),
        (r"Windows NT 5\.1", "Windows XP"),
        (r"Windows NT 5\.0", "Windows 2000"),
        (r"Macintosh.*Mac OS X", "macOS"),
        (r"Android\s+(\d+)", "Android"),  # Captures Android version
        (r"Linux", "Linux"),
        (r"iPhone.*OS\s+(\d+)", "iOS"),
        (r"iPad.*OS\s+(\d+)", "iOS"),
        (r"iPod.*OS\s+(\d+)", "iOS"),
        (r"CrOS", "Chrome OS"),
    ]

    # Device type patterns
    DEVICE_PATTERNS = [
        (r"iPhone", "Mobile"),
        (r"iPod", "Mobile"),
        (r"iPad", "Tablet"),
        (r"Android.*Mobile", "Mobile"),
        (r"Android(?!.*Mobile)", "Tablet"),
        (r"Mobile", "Mobile"),
        (r"Tablet", "Tablet"),
    ]

    # Bot/crawler patterns - combining patterns from both versions
    BOT_PATTERNS = [
        (
            r"bot|crawler|spider|crawl|Googlebot|bingbot|yahoo|slurp|ahref|semrush|baidu|bitdiscovery-suggestions|DigitalOcean|Palo Alto Networks|Expanse",
            "Bot/Crawler",
        ),
    ]

    @classmethod
    def get_device_model_name(cls, device_code):
        """Get the human-readable device name from a Samsung device code."""
        return cls.SAMSUNG_DEVICE_MODELS.get(
            device_code, f"Unknown Samsung Device ({device_code})"
        )

    @classmethod
    def normalize_user_agent(cls, user_agent):
        """
        Normalize a user agent string to categorize browsers, OS, and device types.

        Args:
            user_agent: The raw user agent string

        Returns:
            dict: Containing browser, browser_version, os, os_version, device_type, is_bot, raw
        """
        if not user_agent:
            return {
                "browser": "Unknown",
                "browser_version": None,
                "os": "Unknown",
                "os_version": None,
                "device_type": "Unknown",
                "is_bot": False,
                "raw": user_agent,
            }

        result = {
            "browser": "Unknown",
            "browser_version": None,
            "os": "Unknown",
            "os_version": None,
            "device_type": "Mobile",  # Default to Mobile for Eskola APK
            "is_bot": False,
            "raw": user_agent,
        }

        # Special case for Eskola APK (both formats)
        eskola_match = re.search(
            r"tl\.eskola\.eskola_app(?:\.playstore)?-(\d+\.\d+\.\d+)-release(?:/(\w+))?",
            user_agent,
        )
        if eskola_match:
            result["browser"] = "Eskola APK"
            result["browser_version"] = eskola_match.group(1)
            result["os"] = "Android"
            # Try to extract device model if present
            if eskola_match.group(2):
                device_code = eskola_match.group(2)
                device_name = cls.get_device_model_name(device_code)
                result["os_version"] = f"Device: {device_code} ({device_name})"
            return result

        # Check if it's a bot
        for pattern, _ in cls.BOT_PATTERNS:
            if re.search(pattern, user_agent, re.IGNORECASE):
                result["is_bot"] = True
                result["browser"] = "Bot/Crawler"
                result["device_type"] = "Bot"
                break

        # Detect browser and version
        for pattern, browser in cls.BROWSER_PATTERNS:
            match = re.search(pattern, user_agent)
            if match:
                result["browser"] = browser
                # Get version if available
                if len(match.groups()) > 0 and match.group(1).isdigit():
                    result["browser_version"] = match.group(1)
                break

        # Special case for Dalvik (Android) user agents
        if "Dalvik" in user_agent:
            result["os"] = "Android"
            # Try to extract Android version
            android_match = re.search(r"Android\s+(\d+(?:\.\d+)*)", user_agent)
            if android_match:
                result["os_version"] = android_match.group(1)

        # Detect OS and version for other cases
        if result["os"] == "Unknown":  # Only if not already set by Dalvik check
            for pattern, os in cls.OS_PATTERNS:
                match = re.search(pattern, user_agent)
                if match:
                    result["os"] = os
                    # Extract version if available
                    if len(match.groups()) > 0:
                        result["os_version"] = match.group(1)
                    # Special case for Windows 10
                    if os == "Windows 10":
                        result["os_version"] = "10"
                    break

        # Detect device type (only if not already a bot)
        if not result["is_bot"]:
            for pattern, device in cls.DEVICE_PATTERNS:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    result["device_type"] = device
                    break

        return result

    @classmethod
    def categorize_user_agents(cls, user_agents):
        """
        Group a list of user agent strings into categories.

        Args:
            user_agents: List of (user_agent, count) tuples

        Returns:
            dict: Categorized counts by browser, os, and device type
        """
        categories = {
            "browsers": {},
            "operating_systems": {},
            "device_types": {},
            "bots": 0,
            "total": 0,
        }

        for agent, count in user_agents:
            categories["total"] += count
            info = cls.normalize_user_agent(agent)

            # Add to browser counts
            browser = info["browser"]
            if browser not in categories["browsers"]:
                categories["browsers"][browser] = 0
            categories["browsers"][browser] += count

            # Add to OS counts
            os = info["os"]
            if os not in categories["operating_systems"]:
                categories["operating_systems"][os] = 0
            categories["operating_systems"][os] += count

            # Add to device type counts
            device = info["device_type"]
            if device not in categories["device_types"]:
                categories["device_types"][device] = 0
            categories["device_types"][device] += count

            # Count bots
            if info["is_bot"]:
                categories["bots"] += count

        return categories
