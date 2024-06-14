function getLocation() {
  if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(showPosition, showError);
  } else { 
      alert("Geolocation is not supported by this browser.");
  }
}

function showPosition(position) {
  document.getElementById('latitude').value = position.coords.latitude;
  document.getElementById('longitude').value = position.coords.longitude;
  alert("Location uploaded succesfully!")
}

function showError(error) {
  switch(error.code) {
      case error.PERMISSION_DENIED:
          alert("User denied the request for Geolocation.");
          break;
      case error.POSITION_UNAVAILABLE:
          alert("Location information is unavailable.");
          break;
      case error.TIMEOUT:
          alert("The request to get user location timed out.");
          break;
      case error.UNKNOWN_ERROR:
          alert("An unknown error occurred.");
          break;
  }
}
  