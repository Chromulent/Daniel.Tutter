function get-IndicesOf($Array, $Value) {
    $i = 0
    foreach ($el in $Array) { 
      if ($el -eq $Value) { $i } 
      ++$i
    }
  }
