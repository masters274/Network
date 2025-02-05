class CidrIpAddress {

    #region CONTRUCTORS

    CidrIpAddress( [string] $value ) {

        # Validate the input string to ensure it is a valid CIDR IP address
        if ($value -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$') {

            $this.IP = [IPAddress]::Parse($value.Split('/')[0])
            $this.PrefixLength = [Convert]::ToInt32($value.Split('/')[1])

            [IPAddress]$this.Mask = (([string]'1' * $this.PrefixLength + [string]'0' * (32 - $this.PrefixLength)) -split "(\d{8})" -match "\d" |
                Foreach-Object { [convert]::ToInt32($_, 2) }) -split "\D" -join "."

            $SplitIPAddress = [int[]]@($this.IP -split "\." -match "\d")
            # $SplitIPAddress = $this.IPAddress -split "\." -match "\d"

            $this.ToDecimal = ($SplitIPAddress |
                ForEach-Object -Begin { $i = 3 } -Process { ([Math]::Pow(256, $i)) * $_; $i-- } |
                Measure-Object -Sum).Sum

            $SplitMask = $this.Mask -split "\." -match "\d"

            $this.IPBin = ($SplitIPAddress |
                ForEach-Object { [convert]::ToString($_, 2).PadLeft(8, "0") }) -join "."


            $this.MaskBin = ($SplitMask |
                ForEach-Object { [convert]::ToString($_, 2).PadLeft(8, "0") }) -join "."

            if ((($this.MaskBin -replace "\.").TrimStart("1").Contains("1")) -and (!$this.WildCard)) {
                Write-Warning "Mask Length error, you can try put WildCard"; break
            }

            $this.WildCard = ($SplitMask | ForEach-Object { 255 - $_ }) -join "."

            $myWildCard = $this.WildCard

            $this.Subnet = ((0..31 |
                    Foreach-Object { @($this.IPBin -split "" -match "\d")[$_] -band @($this.MaskBin -split "" -match "\d")[$_] }) -join '' -split "(\d{8})" -match "\d" |
                Foreach-Object { [convert]::ToInt32($_, 2) }) -join "."

            $SplitSubnet = [int[]]@($this.Subnet -split "\." -match "\d")

            $this.SubnetBin = ($SplitSubnet |
                ForEach-Object { [convert]::ToString($_, 2).PadLeft(8, "0") }) -join "."

            $this.Broadcast = (0..3 |
                ForEach-Object { [int]$(@($this.Subnet -split "\." -match "\d")[$_]) + [int]$(@($myWildCard -split "\." -match "\d")[$_]) }) -join "."

            $SplitBroadcast = [int[]]@($this.Broadcast -split "\." -match "\d")

            $this.BroadcastBin = ($SplitBroadcast |
                ForEach-Object { [convert]::ToString($_, 2).PadLeft(8, "0") }) -join "."

            $this.CIDR = $this.Subnet + '/' + $this.PrefixLength

            $this.IPcount = [math]::Pow(2, $(32 - $this.PrefixLength))
        }
        else {

            # Throw an error if the input string is not a valid CIDR IP address
            throw "Error: Invalid CIDR IP address"
        }
    }

    #endregion

    #region PROPERTIES

    $IP
    $Mask
    $PrefixLength
    $WildCard
    $IPcount
    $Subnet
    $Broadcast
    $CIDR
    $ToDecimal
    $IPBin
    $MaskBin
    $SubnetBin
    $BroadcastBin

    #endregion

    #region METHODS

    [object] GetIpArray() {

        $SplitSubnet = $this.Subnet -split "\." -match "\d"

        $SplitBroadcast = $this.Broadcast -split "\." -match "\d"

        $w, $x, $y, $z = @($SplitSubnet[0]..$SplitBroadcast[0]), @($SplitSubnet[1]..$SplitBroadcast[1]), @($SplitSubnet[2]..$SplitBroadcast[2]), @($SplitSubnet[3]..$SplitBroadcast[3])

        return $w |
        Foreach-Object { $wi = $_; $x |
            Foreach-Object { $xi = $_; $y |
                Foreach-Object { $yi = $_; $z |
                    Foreach-Object { $zi = $_; $wi, $xi, $yi, $zi -join '.' } } } }
    }

    [bool] IsInRange( $hostAddress ) {

        return $this.GetIpArray() -contains $hostAddress
    }

    #endregion
}