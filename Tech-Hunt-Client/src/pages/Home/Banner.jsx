import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import banner from "../../assets/banner.jpg";

const Banner = () => {
  return (
    <div className="relative overflow-hidden my-6 font-inter">
      <div
        className="min-h-[600px] lg:min-h-[80vh] rounded-xl relative"
        style={{
          backgroundImage: `linear-gradient(rgba(0,0,0,0.3), rgba(0,0,0,0.5)), url(${banner})`,
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      >
        {/* Subtle geometric accents */}
        <div className="absolute top-0 right-0 w-32 h-32 md:w-48 md:h-48 bg-[var(--bg-accent)]/20 blur-2xl rounded-full -mr-12 -mt-12"></div>
        <div className="absolute bottom-0 left-0 w-40 h-40 md:w-64 md:h-64 bg-[var(--bg-accent)]/20 blur-2xl rounded-full -ml-16 -mb-16"></div>

        {/* Glassmorphism overlay */}
        <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px] rounded-xl"></div>

        <div className="relative z-10 flex items-center justify-center min-h-[600px] px-4">
          <motion.div
            className="max-w-2xl text-center text-white"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <h1 className="chakra text-3xl md:text-5xl lg:text-6xl font-bold mb-6 leading-tight">
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-[var(--bg-accent)] to-blue-400">
                Discover & Share
              </span>
              <br className="md:hidden" /> the Best in Tech
            </h1>
            <p className="text-sm md:text-lg custom-text-secondary mb-8 max-w-xl mx-auto leading-relaxed opacity-90">
              Explore trending innovations, upvote your favorites, and connect with creators driving the future of technology.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/products"
                className="group relative px-6 py-3 custom-bg-accent text-white rounded-lg text-sm font-medium overflow-hidden transition-all hover:shadow-lg hover:shadow-[var(--bg-accent)]/25 hover:scale-105 tooltip tooltip-bottom"
                data-tip="Explore products now"
              >
                <span className="relative z-10 flex items-center justify-center gap-2">
                  Start Exploring
                  <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" />
                </span>
                <div className="absolute inset-0 bg-[var(--bg-accent)]/80 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              </Link>
              <Link
                to="/about"
                className="px-6 py-3 bg-white/10 border border-[var(--bg-accent)]/20 rounded-lg text-sm text-white transition-all hover:bg-white/20 hover:shadow-lg hover:scale-105 tooltip tooltip-bottom"
                data-tip="Learn about Tech Hunt"
              >
                Learn More
              </Link>
            </div>
            <div className="mt-12 inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/10 text-xs font-medium">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
              <span>800+ Products Available</span>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Banner;