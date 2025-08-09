import { motion } from "framer-motion";
import { Users, Briefcase, BarChart, Star } from "lucide-react";

const Impact = () => {
  return (
    <section className="py-12 custom-bg-primary font-inter">
      <div className="container mx-auto px-4 max-w-5xl">
        <div className="text-center mb-12">
          <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
            Impact
          </span>
          <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
            Our Impact
          </h2>
          <p className="text-sm custom-text-secondary max-w-3xl mx-auto">
            We measure our success by the connections we foster and the growth we enable.
          </p>
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.7, staggerChildren: 0.1 }}
          viewport={{ once: true }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          <MetricCard
            icon={<Users size={32} className="custom-text-accent" />}
            metric="$15.2M"
            description="Funding raised by launched products"
            gradient="from-[var(--bg-accent)] to-blue-600"
          />
          <MetricCard
            icon={<Briefcase size={32} className="custom-text-accent" />}
            metric="340+"
            description="Independent creators supported"
            gradient="from-purple-500 to-pink-600"
          />
          <MetricCard
            icon={<BarChart size={32} className="custom-text-accent" />}
            metric="78%"
            description="Of products improved based on feedback"
            gradient="from-green-500 to-teal-600"
          />
          <MetricCard
            icon={<Star size={32} className="custom-text-accent" />}
            metric="25,000+"
            description="Feature requests implemented"
            gradient="from-orange-500 to-red-600"
          />
        </motion.div>
      </div>
    </section>
  );
};

const MetricCard = ({ icon, metric, description, gradient }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      whileHover={{ y: -5, transition: { type: "spring", stiffness: 300 } }}
      transition={{ duration: 0.5 }}
      viewport={{ once: true }}
      className="relative custom-bg-secondary rounded-xl shadow-md hover:shadow-lg transition-all tooltip tooltip-bottom"
      data-tip={description}
    >
      <div className="p-6 relative z-10">
        <div className={`w-12 h-12 mb-4 rounded-lg flex items-center justify-center bg-gradient-to-br ${gradient}`}>
          {icon}
        </div>
        <h3 className="text-2xl font-bold custom-text-primary mb-1">{metric}</h3>
        <p className="text-sm custom-text-secondary">{description}</p>
      </div>
      <div className={`absolute -top-3 -right-3 w-12 h-12 rounded-full bg-gradient-to-br ${gradient} opacity-20 blur-md`}></div>
    </motion.div>
  );
};

export default Impact;