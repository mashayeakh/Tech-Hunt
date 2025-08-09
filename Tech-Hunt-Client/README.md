<div align="center">
  <img src="public/Tech Hunt Mockup.png" alt="Tech Hunt Logo">
</div>

# Tech Hunt

A dynamic platform for discovering and sharing tech products like web apps, AI tools, software, games, and mobile applications. This platform enables users to submit, upvote, and review products, with roles for normal users, moderators, and admins.

## 🌟 Features

### General Features
- **Responsive Design**: Fully responsive for mobile, tablet, and desktop views.
- **Authentication**: User login and registration with email/password and Google Sign-In.
- **Role-Based Access**: Roles for normal users, moderators, and admins with distinct permissions.
- **Environment Variable Security**: Firebase and MongoDB credentials are hidden using environment variables.

### User-Specific Features
- Browse and upvote products.
- Submit new products for review.
- Post reviews with ratings and comments.
- Report inappropriate or low-quality products.

### Moderator-Specific Features
- Approve or reject submitted products.
- Handle reported products.
- Mark products as "featured."

### Admin-Specific Features
- Manage user roles (e.g., make moderators or admins).
- Monitor site statistics with pie charts.
- Add, edit, and manage coupons.

### Dashboard Features
- **User Dashboard**:
  - View and edit profile.
  - Add new products (restricted unless subscribed).
  - Manage personal products (update or delete).

- **Moderator Dashboard**:
  - Review product submissions and handle reported content.

- **Admin Dashboard**:
  - View user statistics and manage user roles.
  - Add and manage coupons.

### Additional Functionalities
- JWT for secure private routes.
- Pagination and search functionality for product listings.
- Coupons for discounts on membership subscriptions.
- Membership options to unlock unlimited product submissions.

---

## 🚀 Live Demo
[Tech Hunt Live Site](https://tech-hunt-39126.web.app/)
[Alternative Live Site](https://tech-hunt-ornobaadi.surge.sh/)


---

## Server Side Code
[Tech Hunt Server](https://github.com/ornobaadi/Tech-Hunt-Server)

---

## 🛠️ Technologies Used

- **Frontend**: React.js, Tailwind CSS 4 (beta), Daisy UI 5 (beta)
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Authentication**: Firebase
- **Deploymeny**: Vercel
- **Other Tools**: JWT, React-Toastify, react-tag-input, 

---

## 📖 Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ornobaadi/Tech-Hunt-Client.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Tech-Hunt-Client
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a `.env` file in the root directory and add the following:
   ```env
   REACT_APP_FIREBASE_API_KEY=your-firebase-api-key
   REACT_APP_FIREBASE_AUTH_DOMAIN=your-firebase-auth-domain
   MONGODB_URI=your-mongodb-connection-string
   JWT_SECRET=your-jwt-secret
   ```
5. Start the development server:
   ```bash
   npm run dev
   ```

---

## 🎨 Folder Structure

```
├── src
│   ├── components      # Reusable React components
│   ├── pages           # Page-specific components
│   ├── services        # API and database interactions
│   ├── utils           # Helper functions and constants
│   ├── styles          # Tailwind and custom CSS styles
│   ├── App.js          # Main application file
│   └── index.js        # Entry point
└── server
    ├── controllers     # Backend logic for routes
    ├── routes          # API endpoints
    ├── models          # Database models
    ├── middleware      # Authentication and other middlewares
    └── server.js       # Main backend file
```

---

## 📊 Statistics (Admin Feature)

The statistics page includes:
- Total products: Accepted, Pending, Rejected.
- Total users.
- Total reviews.

---

## 📌 Future Enhancements

- **Downvote Feature**: Allow users to downvote products.
- **Advanced Search**: Enable filtering by categories or tags.
- **Analytics Dashboard**: Show detailed user and product insights.

---


## 📧 Contact

For questions or suggestions, feel free to contact me:

- **Email**: aadi4789@gmail.com
- **GitHub**: [OrnobAadi](https://github.com/ornobaadi)

Happy coding! 🎉

