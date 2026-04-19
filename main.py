

from analyzer import UserConfig, analyze_network
from report import generateReport
from collector import get_active_config

from pathlib import Path

# for y or n inputs by the user to the prompts made by the script. 
def bool_helper(prompt: str) -> bool:
    while True:
        value = input(prompt).strip().lower()
        if value in ["yes", "y"]:
            return True
        if value in ["no", "n"]:
            return False
        print("Please enter yes(y) or no(n).")

# prompts user for the mode
def getMode() -> str:
    while True:
        mode = input("Choose mode (auto/manual): ").strip().lower()
        if mode in ["auto", "manual"]:
            return mode
        print("Please choose between 'auto' or 'manual'.")

# if manual is chosen
def getManualConfig() -> UserConfig:
    ssid = input("Enter SSID: ").strip()
    encryption_standard = input("Enter encryption type (Open, WEP, WPA, WPA2, WPA3): ").strip()
    cipher = input("Enter cipher type (None, TKIP, AES, CCMP): ").strip()
    authentication_type = input("Enter Authentication mode (Personal, Enterprise): ").strip()
    wps = bool_helper("Is WPS enabled yes(y) or no(n)? ")

    return UserConfig(
        ssid=ssid,
        encryption_standard=encryption_standard,
        cipher=cipher,
        authentication_type=authentication_type,
        wps=wps,
    )


def main():
    print("Wireless Encryption Audit Tool")
    print("-" * 40)

    mode = getMode()

    #if auto is chosen
    if mode == "auto":
        config = get_active_config()

        if config.ssid == "UNKNOWN" and config.encryption_standard == "UNKNOWN":
            print("\nNo active Wi-Fi connection could be detected.")
            change_mode = bool_helper("Would you like to switch to manual mode? (y/n): ")

            if change_mode:
                config = getManualConfig()
            else:
                print("Exiting application.")
                return
        else:
            print("Wireless configuration detection completed.")
    else:
        config = getManualConfig()
        print("Wireless configuration collected.")

    result = analyze_network(config)
    report_txt = generateReport(result)

    print()
    print(report_txt)

    
    saved_file = save_report(config.ssid, report_txt)
    print(f"\n Assessment completed! \n \o/ script ended \o/ \n Report can be found here: {saved_file}")  




# save report to a txt file and put it on desktop
def save_report(ssid: str, report: str) -> Path:
    save_path = Path.home() /"OneDrive" /"Desktop" /"Weat_Outputs"
    save_file = f"{ssid}_weat_report.txt".replace(" ","_")
    
    file_path = save_path / save_file
    
    with open(file_path, "w",encoding="utf-8") as file:
        file.write(report)
    
    return file_path
    


if __name__ == "__main__":
    try:
        main()
        input("Enter any key to exit.....") #added this so the terminal window will stay and not close. 
    except Exception as e:
        print("Application error: {e}")
        
### EOF ### 
    
    
