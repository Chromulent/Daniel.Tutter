# Define Function that will look for a given string for youtube videos.
# requires youtube Api Key
# Reference Link: https://www.reddit.com/r/PowerShell/comments/7x8we5/a_script_to_grab_the_newest_videolink_on_youtube/
$apikey=""
Function Launch-Video($VideoID)
	{
	$url = "https://www.youtube.com/embed/$VideoID"
	$ie = new-object -ComObject "InternetExplorer.Application"
	$ie.MenuBar = $False
	$ie.StatusBar = $False
	$ie.ToolBar = $False
	$ie.AddressBar = $False
	$ie.Top = 600
	$ie.Left = 1100
	$ie.Width = 480
	$ie.Height = 298
	$ie.Navigate($url)
	$ie.visible = $True
	}

Function Search-YouTube($query, $results=10)
    {

    $params = @{
		type='video';
		q=$query;
                part='snippet';
                maxResults=$results;
                key='GOOGLE API KEY HERE'  
		}   

    $response = Invoke-RestMethod -Uri https://www.googleapis.com/youtube/v3/search -Body $params -Method Get
    for ( $i=1; $i -le $Response.items.count; $i++)
        {
        Write-Host "$i. $($response.items[$i-1].snippet.title)" -ForegroundColor Cyan
        }
    $Selection = Read-host "Selection"
    Launch-Video -VideoID ($response.items[$selection-1].id.videoId)
    }

Search-YouTube "$(Read-Host -Prompt 'What video would you like to search on youtube?')"