fn main() {
    let mut windows_attributes = tauri_build::WindowsAttributes::new();

    // Embed manifest requiring admin privileges (for TUN/kill switch)
    windows_attributes = windows_attributes.app_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"#);

    tauri_build::Builder::new()
        .windows_attributes(windows_attributes)
        .build();
}
