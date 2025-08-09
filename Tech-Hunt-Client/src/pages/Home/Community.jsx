import { useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { Code, Sparkles, Users } from "lucide-react";

const Community = () => {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <section className="py-12 custom-bg-primary font-inter">
      <div className="container mx-auto px-4 max-w-5xl">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          onViewportEnter={() => setIsVisible(true)}
        >
          <div className="text-center mb-12">
            <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
              Join Our Community
            </h2>
            <p className="text-sm custom-text-secondary max-w-3xl mx-auto">
              Tech Hunt is built by and for technology enthusiasts, developers, designers, product managers, and curious minds.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-xl font-bold custom-text-primary mb-4">Who's Tech Hunt For?</h3>
              <div className="space-y-4">
                <UserTypeItem
                  icon={<Code size={24} className="custom-text-accent" />}
                  title="Developers & Creators"
                  description="Launch your products to an engaged audience and receive valuable feedback"
                />
                <UserTypeItem
                  icon={<Sparkles size={24} className="custom-text-accent" />}
                  title="Early Adopters"
                  description="Discover cutting-edge tools before they become mainstream"
                />
                <UserTypeItem
                  icon={<Users size={24} className="custom-text-accent" />}
                  title="Investors & Industry Watchers"
                  description="Spot emerging trends and promising startups before they break through"
                />
              </div>
            </div>
            <CommunityStats isVisible={isVisible} />
          </div>
        </motion.div>
      </div>
    </section>
  );
};

const UserTypeItem = ({ icon, title, description }) => {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      className="flex gap-4 items-start tooltip tooltip-bottom"
      data-tip={title}
    >
      <div className="custom-bg-accent/10 p-3 rounded-full h-12 w-12 flex items-center justify-center flex-shrink-0">
        {icon}
      </div>
      <div>
        <h4 className="text-lg font-semibold custom-text-primary mb-1">{title}</h4>
        <p className="text-sm custom-text-secondary">{description}</p>
      </div>
    </motion.div>
  );
};

const CommunityStats = ({ isVisible }) => {
  const stats = [
    { value: "5,000+", label: "Active Users" },
    { value: "1,200+", label: "Products" },
    { value: "15,000+", label: "Reviews" },
    { value: "98%", label: "User Satisfaction" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={isVisible ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.6 }}
      className="custom-bg-secondary p-6 rounded-xl shadow-lg"
    >
      <div className="custom-bg-primary rounded-lg p-6">
        <h3 className="text-lg font-bold custom-text-primary mb-4">Community Stats</h3>
        <div className="grid grid-cols-2 gap-4">
          {stats.map((stat, index) => (
            <div key={index} className="custom-bg-secondary p-4 rounded-lg text-center">
              <div className="text-xl font-bold custom-text-accent mb-1">{stat.value}</div>
              <div className="text-xs custom-text-secondary">{stat.label}</div>
            </div>
          ))}
        </div>
        <div className="mt-6">
          <Link
            to="/login"
            className="w-full px-6 py-3 custom-bg-accent text-white rounded-lg text-sm font-medium transition-all hover:scale-105 hover:shadow-lg tooltip tooltip-bottom"
            data-tip="Join the community"
          >
            Join Us Today
          </Link>
        </div>
      </div>
    </motion.div>
  );
};

export default Community;