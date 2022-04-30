const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const n_accounts=3;
let balances={};
let keyMapping={}
let accounts=[];

//Regenerate the balances and create public -> private key mapping
for(let i=0; i<n_accounts; i++) { 
  let ec = new EC('secp256k1');
  let key = ec.genKeyPair();
  //from elliptic docs
  let publicKey=key.getPublic().encode('hex');
  let privateKey=key.getPrivate().toString(16)
  //Random Balances
  balances[publicKey]=Math.floor(Math.random()*100); 
  //Get Random Key Mapping 
  keyMapping[publicKey]=privateKey;
  //List of accounts
  accounts.push(publicKey);
}

//  = {
//   "1": 100,
//   "2": 50,
//   "3": 75,
// }

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, key} = req.body;

  //Part 2:
  //1. Create signed message of sender, recipient and amount from the private key provided 
  //2. Verify that the signed message has come from the public key provided

  //Create signed message from the private key
  let msg= [sender, recipient, amount];
  
  let ec_private = new EC('secp256k1');
  
  const accountKey=ec_private.keyFromPrivate(key);
  
  let signedMsg=accountKey.sign(msg);
  
  let signature ={
    r: signedMsg.r.toString(16),
    s: signedMsg.s.toString(16)
  };
  
  //Verify that the signed message comes from the private key provided 
  let ec_public = new EC('secp256k1');
  let publicKey=ec_public.keyFromPublic(sender, 'hex')

  //Verify the signature matches the public key provided 
  if(publicKey.verify(msg, signature)) { 
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
    console.log(`Signature Verified! ${amount} ETH transferred from ${sender} to ${recipient}.`)

  }
  else {
    console.log('Could not verify signature.')
  }

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
  console.log(`Accounts\n-----------------------------------`);
for(let i=0; i<accounts.length; i++) { 
  console.log(`\n${i+1} :  ${accounts[i]} (${balances[accounts[i]]} ETH)`)
}

console.log(`\nPrivate Keys\n-----------------------------------`);
for(let i=0; i<accounts.length; i++) { 
  console.log(`\n${i+1} :  ${keyMapping[accounts[i]]}`)
}
});

// //Challenge 1 - store balances in public addresses  + log public/private key on start - use elytpic   
// const EC = require('elliptic').ec;
// 

// const ec = new EC('secp256k1');

// // TODO: fill in your hex private key
// const privateKey = "2afe31baa3be8dec55b1869ba828f39912f0634788cae62961b1aafb088159ab";

// const key = ec.keyFromPrivate(privateKey);

// // TODO: change this message to whatever you would like to sign
// const message = "Yusef ChainShot Bootcamp";

// const msgHash = SHA256(message);

// const signature = key.sign(msgHash.toString());

// console.log({
//   message,
//   signature: {
//     r: signature.r.toString(16),
//     s: signature.s.toString(16)
//   }
// });


// const EC = require('elliptic').ec;
// const SHA256 = require('crypto-js/sha256');

// const ec = new EC('secp256k1');

// // TODO: fill in the public key points
// const publicKey = {
//   x: "a3992e0e83093974eda892ad5b6e1aaff06a25fc633270075212c20bbaa24088",
//   y: "28dd403a3ca004b1454dd733e4be9db844690d45718ad15d064716b7419607d6"
// }

// const key = ec.keyFromPublic(publicKey, 'hex');

// // TODO: change this message to whatever was signed
// const msg = "Yusef ChainShot Bootcamp";
// const msgHash = SHA256(msg).toString();

// // TODO: fill in the signature components
// const signature = {
//   r: "f0b83d5a3c4e9f2d36b1ac130833d268fd409b6ecd34b2056fb096cdf3f4060a",
//   s: "7d689265f82ce08d1a989ab44c298faf9af46e8fcd12245489deac1f53bd5302"
// };

// console.log(key.verify(msgHash, signature));
