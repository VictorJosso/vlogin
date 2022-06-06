const appwrite = new Appwrite();
let called = false;

appwrite
    .setEndpoint('https://appwrite.josso.fr/v1')
    .setProject('6299b7aec8211a153de2')
;




function login() {
    if (called) {
        return
    }
    called = true;
    let messageDiv = document.getElementsByClassName("card__zone-5").item(0)
    let usernameField = document.getElementById("username")
    let passwordField = document.getElementById("password")

    appwrite.account.createSession(usernameField.value, passwordField.value).then(
        (response) => {
            console.log(response)
            let queryString = new URLSearchParams(window.location.search);
            let serviceID = queryString.get("service")
            let callbackURL = queryString.get("url")
            appwrite.account.createJWT().then(response2 => {
                window.location.href = "/oauth/grant/?service=" + serviceID + "&url=" + callbackURL + "&token=" + response2.jwt
            }, error => {messageDiv.innerHTML = "<section><p class=\"form-element form-error\">Une erreur est survenue : "+ error.toString() +"</p></section>"})
        }, (error) => {
            console.log(error)
            messageDiv.innerHTML = "<section><p class=\"form-element form-error\">L'identifiant ou le mot de passe n'est pas reconnu.</p></section>"
        }
    )


}
