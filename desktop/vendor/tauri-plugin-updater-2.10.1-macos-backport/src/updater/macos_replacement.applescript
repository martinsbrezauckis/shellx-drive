on replacement_command(sourcePath, archivePath, stagingPath, backupPath, expectedDigest, replacementScript)
    return "/bin/sh -c " & quoted form of replacementScript & " shellx-drive-updater " & quoted form of sourcePath & " " & quoted form of archivePath & " " & quoted form of stagingPath & " " & quoted form of backupPath & " " & quoted form of expectedDigest
end replacement_command

on replace_app(sourcePath, archivePath, stagingPath, backupPath, expectedDigest, replacementScript)
    set command to replacement_command(sourcePath, archivePath, stagingPath, backupPath, expectedDigest, replacementScript)
    do shell script command with administrator privileges
end replace_app
