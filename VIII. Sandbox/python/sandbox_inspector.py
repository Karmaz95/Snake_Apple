import os
import plistlib
import argparse

class SandboxInspector:
    def __init__(self, home_dir):
        self.home_dir = home_dir
    
    def container_exists(self, bundle_id):
        # Construct the expected path of the container
        container_path = os.path.join(self.home_dir, 'Library', 'Containers', bundle_id)
        
        # Check if the path exists
        return os.path.exists(container_path)
    
    @staticmethod
    def get_bundle_id(app_path):
        # Construct the path to the Info.plist file
        info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')
        
        # Read the Info.plist file to get the bundle identifier
        with open(info_plist_path, 'rb') as f:
            plist = plistlib.load(f)
            return plist.get('CFBundleIdentifier')
    
    def get_metadata(self, bundle_id):
        # Construct the path to the metadata plist file
        metadata_plist_path = os.path.join(self.home_dir, 'Library', 'Containers', bundle_id, '.com.apple.containermanagerd.metadata.plist')
        
        if os.path.exists(metadata_plist_path):
            with open(metadata_plist_path, 'rb') as f:
                plist = plistlib.load(f)
                return plistlib.dumps(plist, fmt=plistlib.FMT_XML).decode('utf-8')
        else:
            return None
    
    def get_redirectable_paths(self, bundle_id):
        # Construct the path to the metadata plist file
        metadata_plist_path = os.path.join(self.home_dir, 'Library', 'Containers', bundle_id, '.com.apple.containermanagerd.metadata.plist')
        
        if os.path.exists(metadata_plist_path):
            with open(metadata_plist_path, 'rb') as f:
                plist = plistlib.load(f)
                redirectable_paths = plist.get('MCMMetadataInfo', {}).get('SandboxProfileDataValidationInfo', {}).get('RedirectablePaths', [])
                return redirectable_paths
        else:
            return None

    def get_sandbox_profile_data(self, bundle_id):
        # Construct the path to the metadata plist file
        metadata_plist_path = os.path.join(self.home_dir, 'Library', 'Containers', bundle_id, '.com.apple.containermanagerd.metadata.plist')

        if os.path.exists(metadata_plist_path):
            with open(metadata_plist_path, 'rb') as f:
                plist = plistlib.load(f)
                sandbox_profile_data = plist.get('MCMMetadataInfo', {}).get('SandboxProfileData', None)
                return sandbox_profile_data
        else:
            return None

    def parse_sandbox_profile_data(self, sandbox_profile_data):
        # Placeholder for actual parsing logic
        
        # This function will take raw bytes and interpret them as Sandbox Profile Language (SBPL)
        if sandbox_profile_data:
            return sandbox_profile_data# sandbox_profile_data.decode('utf-8', errors='ignore')
        return None

def main():
    parser = argparse.ArgumentParser(description="Inspect sandbox containers for macOS apps.")
    parser.add_argument('-p', '--path', type=str, required=True, help="Path to the application (e.g., /Applications/Notes.app)")
    parser.add_argument('-m', '--metadata', action='store_true', help="Print the .com.apple.containermanagerd.metadata.plist contents")
    parser.add_argument('-r', '--redirectable', action='store_true', help="Print the redirectable paths")
    parser.add_argument('-s', '--sandbox_profile_data', action='store_true', help="Print the SandboxProfileData bytes")
    args = parser.parse_args()
    
    app_path = args.path
    inspector = SandboxInspector(os.path.expanduser("~"))
    
    bundle_id = inspector.get_bundle_id(app_path)
    if bundle_id:
        exists = inspector.container_exists(bundle_id)
        # print(f"Container for {bundle_id} exists: {exists}")
        
        if args.metadata:
            metadata = inspector.get_metadata(bundle_id)
            if metadata:
                #print(f"Metadata for {bundle_id}:\n{metadata}")
                print(f"{metadata}")
            else:
                print(f"No metadata plist found for {bundle_id}.")
        
        if args.redirectable:
            redirectable_paths = inspector.get_redirectable_paths(bundle_id)
            if redirectable_paths:
                print(f"Redirectable paths for {bundle_id}:")
                for path in redirectable_paths:
                    print(f"{path}")
            else:
                print(f"No redirectable paths found for {bundle_id}.")

        if args.sandbox_profile_data:
            sandbox_profile_data = inspector.get_sandbox_profile_data(bundle_id)
            if sandbox_profile_data:
                parsed_data = inspector.parse_sandbox_profile_data(sandbox_profile_data)
                print(f"SandboxProfileData for {bundle_id}:\n{parsed_data}")
            else:
                print(f"No SandboxProfileData found for {bundle_id}.")
    else:
        print("Unable to find the CFBundleIdentifier. Please check the app path.")

if __name__ == "__main__":
    main()