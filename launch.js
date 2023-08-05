function getFhirData() {
    const clientId = document.querySelector('input').value;
    console.log(clientId);
    FHIR.oauth2.authorize({
      'client_id': '6267b480-d0e8-445b-bc76-3691adc4ef04',
      'scope': 'user/Patient.read user/Practitioner.read launch openid profile offline_access fhirUser',
      'redirect_uri': 'https://raw.githack.com/farhan2206/bay-smart-on-fhir-sample-app/main/app.html'
    });
  }
  