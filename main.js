const express = require('express');
const app = express();
app.use(express.json());
const https = require('https');
app.set("port", 8080);

// Jwt modules
var jwksClient = require('jwks-rsa');
var jwt = require('jsonwebtoken');

// GCP datastore modules
const { Datastore } = require('@google-cloud/datastore');
const datastore = new Datastore();


const localIp = "https://as05-423510.uc.r.appspot.com"
const client_info = {
    'domain': 'as05-nodejs.us.auth0.com',
    "grant_type": "password",
    "client_id": "bUSe71gDfr7lCrkOWenXIpKvFXwoTVGR",
    "client_secret": "u7kkE-nRrvrIKCKTjwnH4OMHUm8nMnyU6zOOSmzBd47ODKL-M75-YtZZHNdJk0Cv"
}

/*******************************************
 * Jwt checking functions
*******************************************/
const client = jwksClient({ jwksUri: 'https://' + client_info.domain + '/.well-known/jwks.json' });
function getKey(header, next) {
    client.getSigningKey(header.kid, function (err, key) {
        var signingKey = key.publicKey || key.rsaPublicKey;
        next(null, signingKey);
    });
}
async function verify_jwt(req, payload) {
    if (req.headers.authorization && req.headers.authorization.split(" ")[0] === "Bearer") {
        const token = req.headers.authorization.split(" ")[1];
        let p = new Promise((resolve, reject) => {
            jwt.verify(token, getKey, function (err, decoded) {
                if (err) reject(err);
                else resolve(decoded);
            });
        });
        await p.then(
            function (value) { payload = value; },
            function (error) { console.log(error); }
        )
        return payload;
    } else {
        return null;
    }
}

/*******************************************
 * HATEOAS functions
*******************************************/
function getUrlB(req, obj, C_OR_R_OR_O) {
    const ip2 = localIp;
    if (C_OR_R_OR_O === 'c' || C_OR_R_OR_O === 'C') {
        var newUrl = ip2 + req.url + '/' + obj.id;
    } else if (C_OR_R_OR_O === 'r' || C_OR_R_OR_O === 'R') {
        var newUrl = ip2 + req.url;
    } else {
        var newUrl = ip2 + '/businesses/' + obj.id;
    }
    obj.self = newUrl;
    return obj;
}

/*******************************************
*    ROUTES
*******************************************/
// 1. Generate a JWT
app.post('/login', async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;
        const body = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_info.client_id,
            "client_secret": client_info.client_secret
        }
        const dataString = JSON.stringify(body);

        const options = {
            hostname: client_info.domain,
            path: '/oauth/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': dataString.length,
            }
        };
        let p = new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk.toString(); });
                res.on('end', () => { resolve(JSON.parse(data)) });
            });
            req.on('error', (err) => { reject(err); })
            req.write(dataString);
            req.end();
        });
        await p.then(
            function (value) { res.status(200).send(value).end(); },
            function (error) { console.log(error); }
        )
    } catch (err) {
        console.log(err);
        res.status(400).send("400 Bad Request").end();
    }
});

// 2.Decode a JWT
app.get('/decode', async (req, res) => {
    try {
        var payload = await verify_jwt(req, payload);
        res.status(200).send(payload).end();
    } catch (err) {
        console.log(err);
        res.status(400).send("400 Bad Request").end();
    }
});

// 3. Create a Business
app.post('/businesses', async function (req, res) {
    let data = req.body;
    if (Object.keys(data).length < 6) {
        errBody = { Error: "The request body is missing at least one of the required attributes" };
        res.status(400).send(errBody);
    } else {
        var payload = await verify_jwt(req, payload);
        if (!payload) return res.status(401).send("Invalid JWK").end();
        const key = datastore.key('Business');
        const newData = {
            name: req.body.name,
            owner_id: payload.sub,
            street_address: req.body.street_address,
            city: req.body.city,
            state: req.body.state,
            zip_code: req.body.zip_code,
            inspection_score: req.body.inspection_score
        };
        datastore.save({ key: key, data: newData }, (err) => {
            if (!err) {
                datastore.get(key, function (err, entity) {
                    console.log(entity)
                    const resBody = Object.assign({ id: parseInt(key.path[0]) }, entity);
                    res.status(201).send(getUrlB(req, resBody, 'c'));
                });
            }
        });
    }
});

// 4. Get a Business
app.get("/businesses/:business_id", async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) return res.status(401).send("Invalid JWK").end();
    const key = datastore.key(['Business', parseInt(req.params.business_id)]);
    datastore.get(key, function (err, entity) {
        if (err) res.end(err);
        else if (entity === undefined || payload.sub !== entity.owner_id) {
            errBody = { Error: "No business with this business_id exists" };
            res.status(403).send(errBody);
        } else {
            const resBody = Object.assign({ id: parseInt(key.path[1]) }, entity);
            res.status(200).send(getUrlB(req, resBody, 'r'));
        }
    });
});

// 5. List all Businesses for an Owner
app.get("/businesses", async function (req, res) {
    var resBody = [];
    var payload = await verify_jwt(req, payload);
    if (!payload) {
        const query = datastore.createQuery('Business');
        datastore.runQuery(query, (err, entities) => {
            if (entities.length !== 0) {
                entities.forEach(function (arrayItem) {
                    delete arrayItem.inspection_score;
                    arrayItem = getUrlB(req, arrayItem, 'o');
                    resBody.push(Object.assign({ id: parseInt(arrayItem[datastore.KEY].id) }, arrayItem));
                });
            };
            res.status(200).send(resBody).end();
        });
    } else {
        const oValue = payload.sub;
        const query = datastore.createQuery('Business').filter('owner_id', oValue);
        datastore.runQuery(query, (err, entities) => {
            if (entities.length !== 0) {
                entities.forEach(function (arrayItem) {
                    arrayItem = getUrlB(req, arrayItem, 'o');
                    resBody.push(Object.assign({ id: parseInt(arrayItem[datastore.KEY].id) }, arrayItem));
                });
            };
            res.status(200).send(resBody).end();
        });
    }
});

// 6. Delete a Business
app.delete('/businesses/:business_id', async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) return res.status(401).send("Invalid JWK").end();

    const key = datastore.key(['Business', parseInt(req.params.business_id)]);
    datastore.get(key, function (err, entity) {
        if (entity === undefined || entity.owner_id !== payload.sub) {
            errBody = { Error: "No business with this business_id exists" };
            res.status(403).send(errBody);
        } else {
            datastore.delete(key, (err) => {
                if (err) res.send(err);
                else res.sendStatus(204);
            });
        }
    });
});

app.listen(app.get('port'));
console.log('Express started on local.');