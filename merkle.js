var crypto = require('crypto');

var blockHex = "00000020"
"fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000"
"acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6"
"91cfa859"
"16ca061a"
"00000000";

var transactionList = ["42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e",
    "94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4",
    "959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953",
    "a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2",
    "62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577",
    "766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba",
    "e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208",
    "921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e",
    "15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321",
    "1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0",
    "3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d"];

var transactionList2 = ['32650049a0418e4380db0af81788635d8b65424d397170b8499cdc28c4d27006','30861db96905c8dc8b99398ca1cd5bd5b84ac3264a4e1b3e65afa1bcee7540c4']

var merkleProof = {
    merkleRoot: "",
    hashes: [],
    depth: 0,
    logN: 0
};

function group_hashes(file_hashes){
    merkleProof.depth++;
    var groups = [];
    var remaining = file_hashes.splice(2);
    while(file_hashes.length > 0){
        // little endian
        a1 = Buffer.from(file_hashes[0],'hex').reverse();
        b1 = Buffer.from(file_hashes[1],'hex').reverse();
        // concat
        c1 = [a1, b1];
        c1 = Buffer.concat(c1);
        // sha256 2 times
        h = crypto.createHash('sha256').update(c1).digest();
        h = crypto.createHash('sha256').update(h).digest();
        // to big enndian
        h = h.reverse();

        h = h.toString('hex');
        groups.push(h);
        merkleProof.hashes.push([file_hashes[0], file_hashes[1], h]);
        file_hashes = remaining;
        remaining = file_hashes.splice(2);
    }
    return groups;
}

function merkle_hash(file_hashes){
    var len = file_hashes.length;
    while(len % 2 !== 0){
        file_hashes.push(file_hashes[len-1]);
        len = file_hashes.length;
    }

    file_hashes = group_hashes(file_hashes);

    if(file_hashes.length === 1){
        return file_hashes.pop();
    }
    else{
        return merkle_hash(file_hashes);
    }
}

function merkle_proof(file_hashes, candidateHash, indexOfTx){
    var mRoot = merkle_hash(file_hashes);
    merkleProof.merkleRoot = mRoot;
    merkleProof.logN = (Math.pow(2, merkleProof.depth) + indexOfTx);
    var merkleProofResult = [];
    var searchHash = candidateHash;
    // loop through result
    var result = true;
    while(result!=false){
        for(var hash in merkleProof.hashes){
            if(merkleProof.hashes[hash][0] == searchHash||merkleProof.hashes[hash][1] == searchHash){
                merkleProofResult.push(merkleProof.hashes[hash][2]);
                searchHash = merkleProof.hashes[hash][2];
            }
            else{
                result = false;
            }
        }
    }
    return merkleProofResult;
}

// for question 1
var merkleresult = merkle_proof(transactionList, "e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208", 6);
console.log(merkleProof);
console.log(merkleresult);

var version = "00000020";
var prevBlock = "fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000"
var merkleRoot = "acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6"
var times = "91cfa859";
var bits = "16ca061a";
var nonce = "00000000";

// different from our result, not a valid transaction

// for question 2
var toVerify = "e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208"
var toVerifyIndex = 6;
var givenDepth = 4; // from proof
var mroot = "4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301";
var mproof = ["9ed0a5430b5b530822b1ce1b2b9a03d513c888aaa3f028f041bf143efd8c1b92",
"1dc4b438b3a842bcdd46b6ea5a4aac8d66be858b0ba412578027a1f1fe838c51",
"156f3662b07aaa4a0d9762faaa8c18afe4c211ff92eb1eae1952aa66627bbf2e",
"524c93c6dd0874c5fd9e4e57cfe83176e3c2841c973afb4043d225c22cc52983"]
var logN = (Math.pow(2, givenDepth) + toVerifyIndex).toString('2');
console.log(logN);
console.log(toVerify);
for(var c=0; c < logN.length-1; c++){
    // '0' mean left
    if(logN[logN.length-c-1]=='0'){
        toVerify = merkle_hash([toVerify, mproof[c]]);
        console.log('left');
    }
    // '1' mean right
    else{
        toVerify = merkle_hash([mproof[c], toVerify]);
        console.log('right');
    }
    console.log(toVerify);
}
console.log("result: " + (mroot == toVerify));

