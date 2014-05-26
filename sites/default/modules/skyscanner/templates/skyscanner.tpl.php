<div class="skyscanner-flights"><?php print variable_get('olly4ray_skyscanner_flights'); ?></div>
<div class="skyscanner-hotels"><?php print variable_get('olly4ray_skyscanner_hotels'); ?></div>
<div class="skyscanner-weather">
  <div class="skyscanner-weather-title">Weather in Bali</div>
  <ul>
<?php

$url = "http://api.openweathermap.org/data/2.5/weather?q=bali,seminyak&units=metric";

$string = file_get_contents($url);
$json_a=json_decode($string,true);

echo "<li>".$json_a['name']."</li>";
echo "<li>Sunrise: ".date('h:i:s A', $json_a['sys']['sunrise'])."</li>";
echo "<li>Sunset: ".date('h:i:s A', $json_a['sys']['sunset'])."</li>";
echo "<li>Desc: ".$json_a['weather']['0']['description']."</li>";
echo "<li>Current Temp: ".$json_a['main']['temp']."&deg;</li>";
echo "<li>Current Humidity: ".$json_a['main']['humidity']."&deg;</li>";
echo "<li>Max Temp: ".$json_a['main']['temp_max']."&deg;</li>";
echo "<li>Min Temp: ".$json_a['main']['temp_min']."&deg;</li>";


//{"coord":{"lon":115.17,"lat":-8.71},
//  "sys":{"message":0.2209,"country":"Indonesia","sunrise":1400624713,"sunset":1400666796},
//  "weather":[{"id":803,"main":"Clouds","description":"broken clouds","icon":"04n"}],
//  "base":"cmc stations","main":{"temp":29.282,"temp_min":29.282,"temp_max":29.282,"pressure":1023.52,"sea_level":1023.2,"grnd_level":1023.52,"humidity":97},
//  "wind":{"speed":7.16,"deg":112.005},
//  "rain":{"3h":0},
//  "clouds":{"all":68},
//  "dt":1400678865,"id":7529270,"name":"Denpasar Barat","cod":200}

?>
  </ul>
</div>