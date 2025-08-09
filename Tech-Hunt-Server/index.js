const express = require('express');
const jwt = require('jsonwebtoken')
const app = express();
const cors = require('cors');
require('dotenv').config()
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 5000;

// middleware
const corsOptions = {
    origin: [
        "https://tech-hunt-ornobaadi.surge.sh",
        "http://localhost:5173",
        "https://tech-hunt-39126.web.app",
        "https://tech-hunt-39126.firebaseapp.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(express.json());



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xd8rz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();


        const productsCollection = client.db("techDB").collection("products");
        const upvoteCollection = client.db("techDB").collection("upvotes");
        const userCollection = client.db("techDB").collection("users");
        const reviewCollection = client.db("techDB").collection("reviews");
        const reportCollection = client.db("techDB").collection("reports");
        const couponCollection = client.db("techDB").collection("coupons");


        // jwt related api
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
            res.send({ token });
        })

        // middlewares
        const verifyToken = (req, res, next) => {
            console.log('Inside verify token', req.headers.authorization);
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'Unauthorized Access' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'Unauthorized Access' })
                }
                req.decoded = decoded;
                next();
            })
        }

        const verifyModerator = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await userCollection.findOne(query);
            const isModerator = user?.role === 'moderator';
            if (!isModerator) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            next();
        }

        // use verifyAdmin after verify Token 
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await userCollection.findOne(query);
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            next();
        }

        const validateProductLimit = async (req, res, next) => {
            try {
                const userEmail = req.body.ownerEmail;

                // Check user's membership status
                const user = await userCollection.findOne({ email: userEmail });

                if (!user?.membershipStatus || user.membershipStatus !== 'active') {
                    // Count existing products for this user
                    const productCount = await productsCollection.countDocuments({ ownerEmail: userEmail });

                    if (productCount >= 1) {
                        return res.status(403).json({
                            error: 'Product limit reached',
                            message: 'Free users can only add one product. Please upgrade to premium to add more products.'
                        });
                    }
                }

                next();
            } catch (error) {
                res.status(500).json({ error: 'Error checking product limit' });
            }
        };

        // Users related apis
        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result);
        })

        app.get('/users/admin/:email', verifyToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            let admin = false;
            if (user) {
                admin = user?.role === 'admin';
            }
            res.send({ admin })
        })


        app.post('/users', async (req, res) => {
            const user = req.body;
            // insert email if user doesnt exist

            const query = { email: user.email }
            const existingUser = await userCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'user already exist', insertedId: null })
            }
            const result = await userCollection.insertOne(user);
            res.send(result);
        })

        app.patch('/users/moderator/:id', verifyToken, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    role: 'moderator'
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc)
            res.send(result);
        });

        app.patch('/users/admin/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;

                // Validate if user exists
                const user = await userCollection.findOne({ _id: new ObjectId(id) });
                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Prevent self-role removal
                if (user.email === req.decoded.email) {
                    return res.status(403).send({ message: 'Cannot modify your own role' });
                }

                const filter = { _id: new ObjectId(id) };
                const updatedDoc = {
                    $set: {
                        role: 'admin'
                    }
                }
                const result = await userCollection.updateOne(filter, updatedDoc);
                res.send(result);
            } catch (error) {
                console.error('Error updating user role:', error);
                res.status(500).send({ message: 'Error updating user role' });
            }
        });


        // Products Collection
        app.get('/products', async (req, res) => {
            try {
                const result = await productsCollection.find().toArray();
                res.send(result);
            } catch (error) {
                console.error("Error fetching products:", error);
                res.status(500).send({ message: "Failed to fetch products" });
            }
        });

        app.post('/products', validateProductLimit, async (req, res) => {
            const item = req.body;
            const result = await productsCollection.insertOne(item);
            res.send(result);
        });

        // Search products endpoint
        app.get('/products/search', async (req, res) => {
            try {
                const searchTerm = req.query.q?.toLowerCase() || '';

                // Create a query that searches in tags array
                const query = searchTerm ? {
                    $or: [
                        { tags: { $regex: searchTerm, $options: 'i' } },
                        { productName: { $regex: searchTerm, $options: 'i' } }
                    ]
                } : {};

                const result = await productsCollection.find(query).toArray();
                res.send(result);
            } catch (error) {
                console.error("Error searching products:", error);
                res.status(500).send({ message: "Failed to search products" });
            }
        });

        // Get single product by ID
        app.get('/product/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await productsCollection.findOne(query);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching product details" });
            }
        });

        // Get all reviews
        app.get('/reviews', async (req, res) => {
            try {
                const result = await reviewCollection.find().toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching all reviews" });
            }
        });

        // Get single product by ID
        app.get('/reviews/:productId', async (req, res) => {
            try {
                const productId = req.params.productId;
                const query = { productId: productId };
                const result = await reviewCollection.find(query).toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching reviews" });
            }
        });

        // Post a review
        app.post('/reviews', verifyToken, async (req, res) => {
            try {
                const review = req.body;
                const result = await reviewCollection.insertOne(review);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error posting review" });
            }
        });

        // Get all reports
        app.get('/reports', verifyToken, verifyModerator, async (req, res) => {
            try {
                const result = await reportCollection.find().toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching reports" });
            }
        });

        // Submit a report
        app.post('/reports', verifyToken, async (req, res) => {
            try {
                const report = req.body;
                // Add the report to reports collection
                const reportResult = await reportCollection.insertOne(report);

                // Update the product to mark it as reported
                await productsCollection.updateOne(
                    { _id: new ObjectId(report.productId) },
                    { $set: { reported: true } }
                );

                res.send(reportResult);
            } catch (error) {
                console.error('Error submitting report:', error);
                res.status(500).send({ message: "Error submitting report" });
            }
        });


        // Upvotes Collection
        app.post('/upvotes', async (req, res) => {
            try {
                const upvoteItem = req.body;
                const productId = upvoteItem.productId;
                const userEmail = upvoteItem.email;

                // Check if user has already upvoted this product
                const existingUpvote = await upvoteCollection.findOne({
                    productId: productId,
                    email: userEmail
                });

                if (existingUpvote) {
                    return res.status(400).json({
                        message: 'You have already upvoted this product'
                    });
                }

                // Check if user is trying to upvote their own product
                const product = await productsCollection.findOne({
                    _id: new ObjectId(productId)
                });

                if (product.ownerEmail === userEmail) {
                    return res.status(400).json({
                        message: 'You cannot upvote your own product'
                    });
                }

                // If validations pass, proceed with the upvote
                await productsCollection.updateOne(
                    { _id: new ObjectId(productId) },
                    { $inc: { upvotes: 1 } }
                );

                // Add the upvote record
                const result = await upvoteCollection.insertOne(upvoteItem);
                res.status(201).json(result);
            } catch (error) {
                console.error('Error processing upvote:', error);
                res.status(500).json({
                    message: 'Error processing upvote'
                });
            }
        });

        app.get('/upvotes', async (req, res) => {
            const email = req.query.email;
            const query = { email: email }
            const result = await upvoteCollection.find(query).toArray();
            res.send(result);
        });

        app.delete('/upvotes/:id', async (req, res) => {
            const id = req.params.id;

            // First get the upvote record to get the product ID
            const upvote = await upvoteCollection.findOne({ _id: new ObjectId(id) });

            if (upvote) {
                // Decrease the product's upvote count
                await productsCollection.updateOne(
                    { _id: new ObjectId(upvote.productId) },
                    { $inc: { upvotes: -1 } }
                );

                // Then delete the upvote record
                const result = await upvoteCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } else {
                res.status(404).send({ message: 'Upvote not found' });
            }
        });


        // Users Collection 
        app.get('/users/:email', async (req, res) => {
            try {
                const email = req.params.email;
                const query = { email: email };
                const result = await userCollection.findOne(query);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching user data" });
            }
        });

        app.patch('/users/remove-role/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $unset: { role: "" }
            }
            const result = await userCollection.updateOne(filter, updatedDoc)
            res.send(result);
        });

        app.patch('/users/:email', async (req, res) => {
            try {
                const email = req.params.email;
                const updatedData = req.body;

                // Find the user first
                const existingUser = await userCollection.findOne({ email });

                // Prepare the update document
                const updateDoc = {
                    $set: {
                        ...updatedData,
                        // If updating membership status, add these fields
                        ...(updatedData.membershipStatus && {
                            membershipStatus: updatedData.membershipStatus,
                            subscriptionDate: updatedData.subscriptionDate,
                            paymentId: updatedData.paymentId,
                            subscriptionAmount: updatedData.subscriptionAmount,
                            couponUsed: updatedData.couponUsed
                        })
                    }
                };

                // Update or insert the user
                const result = await userCollection.updateOne(
                    { email },
                    updateDoc,
                    { upsert: true }
                );

                res.send(result);
            } catch (error) {
                console.error('Error updating user:', error);
                res.status(500).send({ message: "Error updating user data" });
            }
        });

        // Moderator Collection 

        // Get moderator status
        app.get('/users/moderator/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            let moderator = false;
            if (user) {
                moderator = user?.role === 'moderator';
            }
            res.send({ moderator })
        });

        // Get products for review
        app.get('/products/review-queue', verifyToken, verifyModerator, async (req, res) => {
            try {
                const result = await productsCollection.find().toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching products for review" });
            }
        });

        // Update product status
        app.patch('/products/status/:id', verifyToken, verifyModerator, async (req, res) => {
            try {
                const id = req.params.id;
                const { status, featured } = req.body;
                const filter = { _id: new ObjectId(id) };

                // Create update object based on what's provided
                const updateFields = {};
                if (status) updateFields.status = status;
                if (featured !== undefined) updateFields.featured = featured;

                const updateDoc = {
                    $set: updateFields
                };

                const result = await productsCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error updating product status" });
            }
        });

        // Update Product Details
        app.patch('/products/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const updatedData = req.body;
                const filter = { _id: new ObjectId(id) };

                // Keep the status and owner info unchanged
                const { status, ownerName, ownerEmail, ownerImage, ...updateFields } = updatedData;

                const updateDoc = {
                    $set: updateFields
                };

                const result = await productsCollection.updateOne(filter, updateDoc);
                res.send(result);
            } catch (error) {
                console.error('Error updating product:', error);
                res.status(500).send({ message: "Error updating product" });
            }
        });

        // Delete myProducts 
        app.delete('/products/:id', verifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };

                // First verify if the user owns this product
                const product = await productsCollection.findOne(query);

                if (!product) {
                    return res.status(404).send({ message: "Product not found" });
                }

                if (product.ownerEmail !== req.decoded.email) {
                    return res.status(403).send({ message: "Forbidden: You can only delete your own products" });
                }

                const result = await productsCollection.deleteOne(query);
                res.send(result);
            } catch (error) {
                console.error('Error deleting product:', error);
                res.status(500).send({ message: "Error deleting product" });
            }
        });

        // Find the owner info
        app.get('/products/user/:email', verifyToken, async (req, res) => {
            try {
                const email = req.params.email;
                const query = { ownerEmail: email }; // Assuming ownerEmail is the field storing the user's email
                const result = await productsCollection.find(query).toArray();
                res.send(result);
            } catch (error) {
                console.error('Error fetching user products:', error);
                res.status(500).send({ message: "Error fetching user products" });
            }
        });

        // Get reported products
        app.get('/products/reported', verifyToken, verifyModerator, async (req, res) => {
            try {
                const query = { reported: true };
                const result = await productsCollection.find(query).toArray();
                res.send(result);
            } catch (error) {
                console.error('Error fetching reported products:', error);
                res.status(500).send({ message: "Error fetching reported products" });
            }
        });

        // Delete reported product
        app.delete('/products/reported/:id', verifyToken, verifyModerator, async (req, res) => {
            try {
                const id = req.params.id;
                // Delete the product
                const productResult = await productsCollection.deleteOne({ _id: new ObjectId(id) });
                // Delete associated reports
                await reportCollection.deleteMany({ productId: id });
                res.send(productResult);
            } catch (error) {
                console.error('Error deleting reported product:', error);
                res.status(500).send({ message: "Error deleting reported product" });
            }
        });

        // Coupon routes

        app.get('/verify-coupon/:code', async (req, res) => {
            try {
                const code = req.params.code;
                const coupon = await couponCollection.findOne({ code: code });

                if (!coupon) {
                    return res.status(404).send({ message: 'Invalid coupon code' });
                }

                const currentDate = new Date();
                const expiryDate = new Date(coupon.expiryDate);

                if (currentDate > expiryDate) {
                    return res.status(400).send({ message: 'This coupon has expired' });
                }

                res.send(coupon);
            } catch (error) {
                res.status(500).send({ message: 'Error verifying coupon' });
            }
        });

        // Get all coupons
        app.get('/coupons', async (req, res) => {
            try {
                const result = await couponCollection.find().toArray();
                res.send(result);
            } catch (error) {
                console.error('Error fetching coupons:', error);
                res.status(500).send({ message: 'Failed to fetch coupons' });
            }
        });


        app.post('/coupons', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const coupon = req.body;
                const result = await couponCollection.insertOne(coupon);
                res.send(result);
            } catch (error) {
                console.error('Error adding coupon:', error);
                res.status(500).send({ message: "Error adding coupon" });
            }
        });

        app.patch('/coupons/:id', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const id = req.params.id;
                const updatedData = req.body;
                const result = await couponCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updatedData }
                );
                res.send(result);
            } catch (error) {
                console.error('Error updating coupon:', error);
                res.status(500).send({ message: "Error updating coupon" });
            }
        });

        app.delete('/coupons/:id', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await couponCollection.deleteOne(query);
                res.send(result);
            } catch (error) {
                console.error('Error deleting coupon:', error);
                res.status(500).send({ message: "Error deleting coupon" });
            }
        });


        // Payment Stripe Intent
        app.post('/create-payment-intent', async (req, res) => {
            const { price } = req.body;
            const amount = parseInt(price * 100);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            });
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })


        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('tech is booting')
})

app.listen(port, () => {
    console.log(`Tech Hunt is booting on port ${port}`);
})