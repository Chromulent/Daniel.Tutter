
# Written by https://www.reddit.com/user/NotNotWrongUsually/
# On this thread https://www.reddit.com/r/PowerShell/comments/g1mksm/convert_bytes_automatically_to_gb_or_tb_based_on/

function HumanReadableByteSize ($size) {
    switch ($size) {
    {$_ -gt 1TB} {($size / 1TB).ToString("n2") + " TB";break}
    {$_ -gt 1GB} {($size / 1GB).ToString("n2") + " GB";break}
    {$_ -gt 1MB} {($size / 1MB).ToString("n2") + " MB";break}
    {$_ -gt 1KB} {($size / 1KB).ToString("n2") + " KB";break}
    default {"$size B"}
    }
}
# To get to Bytes $ToBytes = GB * 1073741824 
# HumanReadableByteSize($ToBytes)