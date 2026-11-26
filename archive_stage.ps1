$ErrorActionPreference='Stop'
# Этот текст считывается и проверяется пользовательским процессом ДО UAC,
# затем передаётся системному PowerShell в -EncodedCommand, а не исполняется из архива.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE_BASE64__'))
$expected='__MANIFEST_SHA256__'
$source=[IO.Path]::GetFullPath($source).TrimEnd([char]92)
$stage=$null
try {
  # Reflection.Emit не создаёт исходники/сборки компилятора в пользовательском TEMP.
  $an=New-Object Reflection.AssemblyName('StretchBITArchiveNative')
  $ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly($an,[Reflection.Emit.AssemblyBuilderAccess]::Run)
  $mb=$ab.DefineDynamicModule('Native')
  $tb=$mb.DefineType('SbitArchiveNative',[Reflection.TypeAttributes]'Public,Abstract,Sealed')
  function NativeMethod($name,$dll,$result,[Type[]]$parameters) {
    $m=$tb.DefinePInvokeMethod($name,$dll,
      [Reflection.MethodAttributes]'Public,Static,PinvokeImpl',
      [Reflection.CallingConventions]::Standard,$result,$parameters,
      [Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Unicode)
    $m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    if ($name -eq 'GetFileInformationByHandle') {
      [void]$m.DefineParameter(2,[Reflection.ParameterAttributes]::Out,'information')
    }
  }
  NativeMethod 'CreateFileW' 'kernel32.dll' ([IntPtr]) @([string],[uint32],[uint32],[IntPtr],[uint32],[uint32],[IntPtr])
  NativeMethod 'GetFileInformationByHandle' 'kernel32.dll' ([bool]) @([IntPtr],[byte[]])
  NativeMethod 'GetFinalPathNameByHandleW' 'kernel32.dll' ([uint32]) @([IntPtr],[Text.StringBuilder],[uint32],[uint32])
  NativeMethod 'CloseHandle' 'kernel32.dll' ([bool]) @([IntPtr])
  NativeMethod 'MessageBoxW' 'user32.dll' ([int]) @([IntPtr],[string],[string],[uint32])
  $native=$tb.CreateType()
  function SafeName([string]$name) {
    if (!$name -or $name -match '[\\:\x00<>"|?*]' -or [IO.Path]::IsPathRooted($name)) {throw 'Invalid package path'}
    foreach($part in $name.Split('/')) {
      if (!$part -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or
          $part.EndsWith(' ') -or $part -match '^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)') {throw 'Invalid package name'}
    }
    return $name.Replace('/',[IO.Path]::DirectorySeparatorChar)
  }
  function OpenSource([string]$relative) {
    $relative=SafeName $relative
    $h=$native::CreateFileW([IO.Path]::Combine($source,$relative),[uint32]2147483648,1,
      [IntPtr]::Zero,3,[uint32]2097280,[IntPtr]::Zero)
    if ($h -eq [IntPtr](-1)) {throw 'Package file cannot be opened'}
    try {
      $info=New-Object byte[] 52
      if (!$native::GetFileInformationByHandle($h,$info) -or
          ([BitConverter]::ToUInt32($info,0) -band 1040) -ne 0 -or
          [BitConverter]::ToUInt32($info,40) -ne 1) {throw 'Package links are forbidden'}
      $b=New-Object Text.StringBuilder 32768
      $n=$native::GetFinalPathNameByHandleW($h,$b,32768,0)
      if (!$n -or $n -ge 32768) {throw 'Package path is unavailable'}
      $p=$b.ToString()
      if ($p.StartsWith('\\?\UNC\')) {$p='\\'+$p.Substring(8)}
      elseif ($p.StartsWith('\\?\')) {$p=$p.Substring(4)}
      if (!$p.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Package path escapes source'}
      $safe=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($h,$true)
      $stream=New-Object IO.FileStream($safe,[IO.FileAccess]::Read)
      $h=[IntPtr]::Zero
      return $stream
    } finally {if ($h -ne [IntPtr]::Zero) {[void]$native::CloseHandle($h)}}
  }
  function Digest($stream) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally {$sha.Dispose()}
  }
  $input=OpenSource 'archive-files.json'
  try {
    if ($input.Length -gt 16777216 -or (Digest $input) -ne $expected) {throw 'Package manifest changed'}
    $input.Position=0
    $memory=New-Object IO.MemoryStream
    $input.CopyTo($memory)
    $raw=$memory.ToArray()
    $memory.Dispose()
  } finally {$input.Dispose()}
  $data=[Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
  if ($data.format -ne 1 -or $data.edition -notin @('release','test') -or
      !$data.files.'StretchBIT.exe' -or !$data.files.'app/install-mode.json') {throw 'Invalid archive metadata'}
  $names=@($data.files.PSObject.Properties)
  if ($names.Count -gt 100000 -or !$names.Count) {throw 'Invalid file count'}
  $pf=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  $suffix=if($data.edition -eq 'test') {'-test'} else {''}
  $target=[IO.Path]::Combine($pf,'StretchBIT-archive'+$suffix)
  if ($source.Equals($target,[StringComparison]::OrdinalIgnoreCase)) {$target+='-protected'}
  $ds=New-Object Security.AccessControl.DirectorySecurity
  $ds.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  $fs=New-Object Security.AccessControl.FileSecurity
  $fs.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
  $publicDir=New-Object Security.AccessControl.DirectorySecurity
  $publicDir.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
  $publicFile=New-Object Security.AccessControl.FileSecurity
  $publicFile.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)')
  function Trusted([string]$path,[int64]$mask=0x500d0156) {
    if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Target link'}
    $acl=[IO.File]::GetAccessControl($path)
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($owner -notin $trusted) {throw 'Existing program owner is not trusted'}
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $descriptor.DiscretionaryAcl) {throw 'Unrestricted program ACL'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and
          ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
          $rule.IdentityReference.Value -notin $trusted -and
          (([int64]$rule.FileSystemRights -band $mask) -ne 0)) {throw 'Existing program is writable'}
    }
  }
  $ancestor=New-Object IO.DirectoryInfo($pf)
  while ($null -ne $ancestor) {
    Trusted $ancestor.FullName 0x100c0040
    $ancestor=$ancestor.Parent
  }
  if ([IO.Directory]::Exists($target)) {
    Trusted $target
    $pending=New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($target)
    while ($pending.Count) {
      $directory=$pending.Dequeue()
      foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
        Trusted $entry
        if (([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::Directory) -ne 0) {
          $pending.Enqueue($entry)
        }
      }
    }
    $s=[IO.File]::OpenRead([IO.Path]::Combine($target,'archive-files.json'))
    try {if ((Digest $s) -ne $expected) {throw 'Destination manifest differs'}}
    finally {$s.Dispose()}
    foreach($item in $names) {
      $path=[IO.Path]::Combine($target,(SafeName $item.Name))
      if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'Target link'}
      Trusted $path
      $s=[IO.File]::OpenRead($path)
      try {if ((Digest $s) -ne $item.Value) {throw 'A different program already occupies the destination'}}
      finally {$s.Dispose()}
    }
  } else {
    $stage=$target+'.setup-'+[Guid]::NewGuid().ToString('N')
    [void][IO.Directory]::CreateDirectory($stage,$ds)
    $total=[int64]0
    foreach($item in $names) {
      if ($item.Value -notmatch '^[0-9a-f]{64}$') {throw 'Invalid package digest'}
      $relative=SafeName $item.Name
      $s=OpenSource $item.Name
      try {
        $total+=$s.Length
        if ($total -gt 21474836480 -or (Digest $s) -ne $item.Value) {throw 'Package bytes changed'}
        $s.Position=0
        $path=[IO.Path]::Combine($stage,$relative)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path),$ds)
        $out=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,
          [Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,
          65536,[IO.FileOptions]::None,$fs)
        try {$s.CopyTo($out);$out.Flush($true)} finally {$out.Dispose()}
      } finally {$s.Dispose()}
    }
    $out=New-Object IO.FileStream([IO.Path]::Combine($stage,'archive-files.json'),
      [IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,
      [IO.FileShare]::None,65536,[IO.FileOptions]::None,$fs)
    try {$out.Write($raw,0,$raw.Length);$out.Flush($true)} finally {$out.Dispose()}
    $mode=[IO.File]::ReadAllText([IO.Path]::Combine($stage,'app\install-mode.json')) | ConvertFrom-Json
    if ($mode.installed_with_service -ne $false) {throw 'Installer build is not an archive'}
    foreach($f in [IO.Directory]::EnumerateFiles($stage,'*',[IO.SearchOption]::AllDirectories)) {
      [IO.File]::SetAccessControl($f,$publicFile)
    }
    foreach($d in [IO.Directory]::EnumerateDirectories($stage,'*',[IO.SearchOption]::AllDirectories)) {
      [IO.Directory]::SetAccessControl($d,$publicDir)
    }
    [IO.Directory]::SetAccessControl($stage,$publicDir)
    [IO.Directory]::Move($stage,$target)
    $stage=$null
  }
  $start=New-Object Diagnostics.ProcessStartInfo
  $start.FileName=[IO.Path]::Combine($target,'StretchBIT.exe')
  $start.Arguments='--archive-finalize'
  $start.WorkingDirectory=$target
  $start.UseShellExecute=$false
  # Не переносить настройки загрузчика Python/Qt из исходной среды в helper.
  foreach($key in @($start.EnvironmentVariables.Keys)) {
    if ($key -match '^(PYTHON|QT_|QML|_PYI|STRETCHBIT_)') {$start.EnvironmentVariables.Remove($key)}
  }
  $process=[Diagnostics.Process]::Start($start)
  $process.WaitForExit()
  exit $process.ExitCode
} catch {
  if ($stage -and [IO.Directory]::Exists($stage)) {[IO.Directory]::Delete($stage,$true)}
  if ($native) {[void]$native::MessageBoxW([IntPtr]::Zero,('Archive setup failed: '+$_.Exception.Message),'StretchBIT',16)}
  exit 1
}
