import { Firestore } from "@google-cloud/firestore";
let db;
function getFirestore(){if(process.env.FIRESTORE_ENABLED!=="true")return null;if(!db)db=new Firestore({projectId:process.env.FIRESTORE_PROJECT_ID||undefined});return db;}
/** Stores profile metadata only. Never store passwords or provider tokens here. */
export async function saveIdentityProfile(uid,identity){
 const firestore=getFirestore();if(!firestore)return;
 const collection=process.env.FIRESTORE_USERS_COLLECTION||"identityProfiles";
 await firestore.collection(collection).doc(uid).set({uid,issuer:identity.issuer,subject:identity.sub,name:identity.name||null,preferredUsername:identity.preferred_username||null,email:identity.email||null,emailVerified:identity.email_verified===true,picture:identity.picture||null,lastLoginAt:new Date(),updatedAt:new Date()},{merge:true});
}
