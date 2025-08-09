import { useState } from "react";
import { motion } from "framer-motion";
import { Mail } from "lucide-react";

const Newsletter = () => {
  const [email, setEmail] = useState("");
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      setError("Please enter a valid email address");
      return;
    }

    console.log("Email submitted:", email);
    setIsSubmitted(true);
    setError("");
    setEmail("");

    setTimeout(() => {
      setIsSubmitted(false);
    }, 5000);
  };

  return (
    <section className="py-12 custom-bg-primary font-inter">
      <div className="container mx-auto px-4 max-w-5xl text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
            Join Our Newsletter
          </h2>
          <p className="text-sm custom-text-secondary max-w-2xl mx-auto mb-8">
            Stay updated with the latest tech discoveries, product launches, and community events. Be the first to know about tomorrow's tech today.
          </p>

          <div className="max-w-md mx-auto">
            {isSubmitted ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.3 }}
                className="custom-bg-accent text-white p-4 rounded-lg mb-6"
              >
                <p className="font-medium">Thank you for subscribing!</p>
                <p className="text-xs mt-1">We'll keep you updated with the latest Tech Hunt news.</p>
              </motion.div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col md:flex-row gap-3 mb-4">
                <div className="flex-grow relative">
                  <Mail size={20} className="absolute left-3 top-1/2 transform -translate-y-1/2 custom-text-secondary" />
                  <input
                    type="email"
                    placeholder="Enter your email address"
                    className={`w-full pl-10 pr-4 py-2 custom-bg-secondary border ${
                      error ? "border-red-500" : "border-[var(--bg-accent)]/20"
                    } rounded-lg text-sm custom-text-primary focus:outline-none focus:ring-2 focus:ring-[var(--bg-accent)]`}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    aria-label="Email address"
                  />
                  {error && <p className="text-red-500 text-xs mt-1 text-left">{error}</p>}
                </div>
                <button
                  type="submit"
                  className="px-6 py-2 custom-bg-accent text-white rounded-lg text-sm font-medium transition-all hover:scale-105 hover:shadow-lg tooltip tooltip-bottom"
                  data-tip="Subscribe to newsletter"
                >
                  Subscribe
                </button>
              </form>
            )}

            <p className="text-xs custom-text-secondary mt-6">
              By subscribing, you agree to our Privacy Policy and Terms of Service. We respect your privacy and will never share your information.
            </p>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default Newsletter;