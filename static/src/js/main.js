function postbutton() {
    fetch ('/postbutton', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
    })
    .then (response => {
        if (response.ok) {
            console.log(response)
        } else {
            throw new Error('Network response was not ok');
        }
    })
}