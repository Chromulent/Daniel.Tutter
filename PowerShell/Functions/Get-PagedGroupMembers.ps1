Function Get-PagedGroupMembers($groupId) {
    # Gets nested group members for a given group within Okta using Okta.Api
    $totalUsers = 0
    $ArrayVariable = New-Object System.Collections.ArrayList
    $params = @{id = $groupId; paged = $true}
    do {
        $page = Get-OktaGroupMember @params
        $users = $page.objects
        foreach ($user in $users) {
            $justObjPer = $user.profile.email
            $ArrayVariable.Add($justObjPer) > $null
        }
        $totalUsers += $users.count
        $params = @{url = $page.nextUrl; paged = $true}
    } while ($page.nextUrl)
    return $ArrayVariable
}
