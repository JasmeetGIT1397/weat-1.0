from dataclasses import dataclass, field
from typing import List


@dataclass
class UserConfig:
    ssid: str
    encryption_standard: str
    cipher: str
    authentication_type: str
    wps: bool


@dataclass
class Result:
    ssid: str
    score: float
    riskLevel: str
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def analyze_network(config: UserConfig) -> Result:
    score = 10.0
    findings = []
    recommendations = []

    encryption_standard = config.encryption_standard.strip().upper()
    cipher = config.cipher.strip().upper()
    authentication = config.authentication_type.strip().upper()

    if encryption_standard == "OPEN":
        score -= 8
        findings.append("WARNING: The network is open and does not use encryption.")
        recommendations.append("Enable WPA3-Personal or WPA2-AES.")
    elif encryption_standard == "WEP":
        score -= 7
        findings.append("WEP is outdated and insecure.")
        recommendations.append("Enable WPA3-Personal or WPA2-AES.")
    elif encryption_standard == "WPA":
        score -= 5
        findings.append("WPA is a legacy security standard and is no longer recommended.")
        recommendations.append("Upgrade to WPA3-Personal or WPA2-AES for better security.")
    elif encryption_standard == "WPA2":
        findings.append("WPA2 is an acceptable security standard.")
        if cipher == "TKIP":
            score -= 4
            findings.append("TKIP is a legacy encryption method and is weak.")
            recommendations.append("Change cipher suite to AES/CCMP.")
        elif cipher in ["AES", "CCMP"]:
            score -= 2
            findings.append("AES/CCMP provides strong encryption.")
        else:
            score -= 2
            findings.append("Cipher could not be confirmed.")
            recommendations.append("Verify that WPA2 is using AES/CCMP.")
    elif encryption_standard == "WPA3":
        findings.append("WPA3 is the most secure modern Wi-Fi standard.")
        if cipher not in ["AES", "CCMP"]:
            score -= 1
            findings.append("Cipher suite should be reviewed for WPA3 compatibility.")
        else:
            score += 0.5
    else:
        score -= 4
        findings.append("Unknown or unsupported encryption type.")
        recommendations.append("Verify the network configuration.")

    if authentication == "PERSONAL":
        findings.append("The network uses personal authentication.")
    elif authentication == "ENTERPRISE":
        findings.append("The network uses enterprise authentication.")
        score += 0.5
    else:
        findings.append("The authentication method is unknown.")

    if config.wps:
        score -= 2
        findings.append("WARNING: WPS is enabled, which increases the security risk.")
        recommendations.append("Disable WPS.")

    score = max(0.0, min(score, 10.0))

    if score >= 8.5:
        riskLevel = "Low"
    elif score >= 6.5:
        riskLevel = "Moderate"
    elif score >= 4:
        riskLevel = "High"
    else:
        riskLevel = "Critical"

    if not recommendations and riskLevel in ["Low", "Moderate"]:
        recommendations.append("Maintain current settings and update firmware.")

    return Result(
        ssid=config.ssid,
        score=score,
        riskLevel=riskLevel,
        findings=findings,
        recommendations=recommendations,
    )