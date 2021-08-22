<?php # -*- php -*-

# This is a gen4 Google Analytics ID
$google_analytics_id = 'G-EW3K1B3YR6';

print("<script async src=\"https://www.googletagmanager.com/gtag/js?id=$google_analytics_id\"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', '$google_analytics_id');
</script>
");
?>
