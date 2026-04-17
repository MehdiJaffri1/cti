import { MongoClient, Db, ObjectId } from "mongodb";

const uri = process.env.MONGODB_URI!;
const dbName = process.env.DB_NAME;

if (!uri) throw new Error("❌ Missing MONGODB_URI in .env");
if (!dbName) throw new Error("❌ Missing DB_NAME in .env");

// ---- GLOBAL CACHE for Hot Reload (Next.js API speed) ----
let cachedClient: MongoClient | null = null;
let cachedDb: Db | null = null;

export async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  try {
    const client = new MongoClient(uri, {
      tls: true,            // 🔥 MOST IMPORTANT FIX
      serverApi: {
        version: "1",
        strict: true,
        deprecationErrors: true,
      },
    });

    await client.connect();
    const db = client.db(dbName);

    cachedClient = client;
    cachedDb = db;

    return { client, db };
  } catch (err) {
    console.error("MongoDB connection error:", err);
    throw err;
  }
}

// -------------------------------
// All your existing functions below
// -------------------------------

export async function getUserByEmail(email: string) {
  const { db } = await connectToDatabase();
  return await db.collection("users").findOne({ email });
}

export async function getUserById(userId: string) {
  const { db } = await connectToDatabase();
  return await db.collection("users").findOne({ _id: new ObjectId(userId) });
}

export async function createUser(email: string, password: string) {
  const { db } = await connectToDatabase();
  const result = await db.collection("users").insertOne({
    email,
    password,
    createdAt: new Date(),
  });
  return result.insertedId.toString();
}

export async function saveAnalysisReport(email: string, userInput: string, report: string, parsedData: any) {
  const { db } = await connectToDatabase();
  const result = await db.collection("analysisReports").insertOne({
    email,
    userInput,
    report,
    ...parsedData,
    createdAt: new Date(),
  });
  return result.insertedId.toString();
}

export async function getAnalysisHistory(email: string, userInput: string, limit = 5) {
  const { db } = await connectToDatabase();
  
  const reports = await db
    .collection("analysisReports")
    .find({ email, userInput })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  return reports.map((doc) => ({
    id: doc._id.toString(),
    input: doc.userInput,
    report: doc.report,
    confidence: doc.confidence,
    threatLevel: doc.threatLevel,
    firstSeen: doc.firstSeen,
    lastSeen: doc.lastSeen,
    createdAt: new Date(doc.createdAt),
  }));
}

export async function getRecentSearches(email: string, limit = 10) {
  const { db } = await connectToDatabase();
  
  const reports = await db
    .collection("analysisReports")
    .find({ email })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  return reports.map((doc) => ({
    id: doc._id.toString(),
    input: doc.userInput,
    timestamp: new Date(doc.createdAt),
    result: doc,
  }));
}
