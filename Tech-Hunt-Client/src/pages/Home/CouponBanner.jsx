import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import Swal from "sweetalert2";
import { Helmet } from "react-helmet-async";
import { Tag, Calendar, Copy, PackageX, Loader2 } from "lucide-react";

const CouponsPage = () => {
  const [coupons, setCoupons] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCoupons = async () => {
      try {
        const response = await fetch("https://tech-hunt-server-two.vercel.app/coupons");
        const data = await response.json();
        setCoupons(data);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching coupons:", error);
        setLoading(false);
      }
    };

    fetchCoupons();
  }, []);

  const handleCopyCode = (code) => {
    navigator.clipboard.writeText(code);
    Swal.fire({
      position: "top-end",
      icon: "success",
      title: "Coupon code copied to clipboard!",
      showConfirmButton: false,
      timer: 1500,
      toast: true,
      background: "var(--bg-secondary)",
      color: "var(--text-primary)",
    });
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen custom-bg-primary font-inter">
        <Loader2 size={40} className="animate-spin custom-text-accent" aria-label="Loading coupons" />
      </div>
    );
  }

  return (
    <div className="custom-bg-primary min-h-screen py-12 font-inter">
      <Helmet>
        <title>Coupons | Tech Hunt</title>
      </Helmet>

      <div className="container mx-auto px-4 max-w-5xl">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <span className="inline-block px-4 py-1 rounded-full custom-bg-accent text-white font-medium text-xs mb-4">
            EXCLUSIVE OFFERS
          </span>
          <h1 className="chakra text-3xl md:text-4xl font-bold custom-text-primary">
            Available Coupons
          </h1>
          <p className="custom-text-secondary mt-3 max-w-lg mx-auto text-sm">
            Use these coupons during checkout to get amazing discounts on our products
          </p>
        </motion.div>

        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
          initial="hidden"
          animate="visible"
          variants={{
            hidden: { opacity: 0 },
            visible: {
              opacity: 1,
              transition: {
                staggerChildren: 0.1,
              },
            },
          }}
        >
          {coupons.map((coupon) => (
            <motion.div
              key={coupon.id}
              variants={{
                hidden: { opacity: 0, y: 20 },
                visible: { opacity: 1, y: 0 },
              }}
              transition={{ duration: 0.3 }}
              whileHover={{ scale: 1.03, y: -5, transition: { type: "spring", stiffness: 300 } }}
              className="custom-bg-secondary rounded-xl shadow-lg p-6 flex flex-col border border-[var(--bg-accent)]/10 hover:shadow-xl transition-shadow duration-300 tooltip tooltip-bottom"
              data-tip={`Use code: ${coupon.code}`}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="p-2 rounded-full custom-bg-accent/10">
                    <Tag size={20} className="custom-text-accent" />
                  </span>
                  <h2 className="chakra text-xl font-bold custom-text-primary tracking-tight">
                    {coupon.code}
                  </h2>
                </div>
                <span className="px-3 py-1 custom-bg-accent text-white rounded-full text-xs font-medium">
                  {coupon.discountAmount}% OFF
                </span>
              </div>

              <div className="flex-1 space-y-3 mb-6">
                <p className="custom-text-secondary text-sm">{coupon.description}</p>
                <div className="flex items-center text-sm custom-text-secondary">
                  <Calendar size={16} className="mr-1 custom-text-accent" />
                  Valid until:{" "}
                  {new Date(coupon.expiryDate).toLocaleDateString("en-US", {
                    year: "numeric",
                    month: "short",
                    day: "numeric",
                  })}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <button
                  onClick={() => handleCopyCode(coupon.code)}
                  className="custom-text-accent text-sm font-medium hover:custom-text-accent-dark transition-colors tooltip tooltip-bottom"
                  data-tip="Copy coupon code"
                  aria-label={`Copy coupon code ${coupon.code}`}
                >
                  <Copy size={16} className="inline mr-1" /> Click to copy
                </button>
                <Link
                  to={`/dashboard/payment?coupon=${coupon.code}`}
                  className="px-4 py-2 custom-bg-accent text-white rounded-lg text-sm font-medium hover:scale-105 transition-all tooltip tooltip-bottom"
                  data-tip="Apply coupon"
                  aria-label={`Use coupon ${coupon.code}`}
                >
                  Use Now
                </Link>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {coupons.length === 0 && (
          <motion.div
            className="text-center py-16 custom-text-secondary"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <PackageX size={64} className="mx-auto custom-text-accent opacity-30 mb-4" />
            <h3 className="chakra text-xl font-bold custom-text-primary">
              No Coupons Available
            </h3>
            <p className="mt-2 text-sm">
              Check back later for exclusive deals and offers.
            </p>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default CouponsPage;