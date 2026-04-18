# format and generate report
# import Result class from analyzer
from analyzer import Result

def generateReport(result: Result) -> str: 
    lines = [] #holds each of the line as a seperate string. builds the report one line at a time. 
    lines.append("=" * 50)
    lines.append("Wi-Fi Encryption Audit Report")
    lines.append("=" * 50)
    lines.append(f"SSID: {result.ssid}")
    lines.append(f"Risk Score: {result.score}")
    lines.append(f"Level: {result.riskLevel}")
    lines.append("")

#List all findings   
    lines.append("Findings: ") 
    for x in result.findings:
        lines.append(f"- {x}")
    
    lines.append("")
    lines.append("Recommendations: ")
    for r in result.recommendations:
        lines.append(f"- {r}")

    lines.append("")
    return "\n".join(lines) #join all lines into one string