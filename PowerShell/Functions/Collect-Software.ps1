Function Collect-Software { Get-wmiobject Win32_Product | Sort-Object -Property Name | Select-Object -Property Name, Vendor }

# Collect-Software