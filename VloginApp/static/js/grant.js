const appwrite = new Appwrite();

appwrite
    .setEndpoint('https://appwrite.josso.fr/v1')
    .setProject('6299b7aec8211a153de2')
;



function refuse() {
    let queryString = new URLSearchParams(window.location.search);
    let url = queryString.get("url");
    window.location.href = url + "?status=canceled"
}

function accept() {
    let queryString = new URLSearchParams(window.location.search);
    let url = queryString.get("url");
    let service = queryString.get("service");
    appwrite.account.createJWT().then(response2 => {
        window.location.href = "/oauth/validate?service=" + service + "&url=" + url + "&token=" + response2["jwt"]
    }, reason => {});
}