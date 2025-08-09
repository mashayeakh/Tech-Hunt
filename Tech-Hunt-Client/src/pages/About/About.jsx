import { motion } from "framer-motion";
import { Check, Users, Star } from "lucide-react";

const About = () => {
  return (
    <div className="custom-bg-primary min-h-screen font-inter">
      {/* Mission Section */}
      <section className="py-12">
        <div className="container mx-auto px-4 max-w-5xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, staggerChildren: 0.2 }}
            className="flex flex-col md:flex-row items-center gap-8"
          >
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7 }}
              className="md:w-1/2"
            >
              <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
                Purpose
              </span>
              <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
                Our Mission
              </h2>
              <p className="text-sm custom-text-secondary mb-6 leading-relaxed">
                We believe great products should be discovered based on merit, not marketing budgets. Our platform creates a space where innovation thrives regardless of resources.
              </p>
              <div className="space-y-3">
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.1 }}
                  className="flex items-center p-2 custom-bg-secondary rounded-lg"
                >
                  <Check size={16} className="text-[var(--bg-accent)] mr-2" />
                  <span className="text-sm custom-text-primary">Creators gain visibility without massive marketing spend</span>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.2 }}
                  className="flex items-center p-2 custom-bg-secondary rounded-lg"
                >
                  <Check size={16} className="text-[var(--bg-accent)] mr-2" />
                  <span className="text-sm custom-text-primary">Users discover useful tools before they go mainstream</span>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.3 }}
                  className="flex items-center p-2 custom-bg-secondary rounded-lg"
                >
                  <Check size={16} className="text-[var(--bg-accent)] mr-2" />
                  <span className="text-sm custom-text-primary">Community curation ensures quality rises to the top</span>
                </motion.div>
              </div>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7 }}
              className="md:w-1/2"
            >
              <div className="relative">
                <div className="absolute -inset-2 bg-gradient-to-r from-[var(--bg-accent)] to-transparent rounded-xl opacity-20 blur-lg"></div>
                <img
                  src="https://imageio.forbes.com/specials-images/imageserve/66fcdc589e002dcb85799ece/Discover-how-Hybrid-AI-is-revolutionizing-industries-by-combining-the-strengths-of/960x0.jpg?format=jpg&width=960"
                  alt="Our mission illustration"
                  className="rounded-xl shadow-lg relative w-full h-auto"
                />
              </div>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Values Grid Section */}
      <ValuesGrid />

      {/* Team Section */}
      <section className="py-12">
        <div className="container mx-auto px-4 max-w-5xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-12"
          >
            <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
              Our Experts
            </span>
            <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
              Meet Our Team
            </h2>
            <p className="text-sm custom-text-secondary max-w-2xl mx-auto">
              Passionate individuals committed to transforming how we discover technology
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <TeamMember
              name="Ornob Aadi"
              role="Founder & CEO"
              image="https://i.ibb.co.com/HNkhYGc/00000-PORTRAIT-00000-BURST20190124113738260-2.jpg"
            />
            <TeamMember
              name="Abu Jafar"
              role="CTO"
              image="https://i.ibb.co.com/dJr1vX1r/IMG-20220709-023311-731.jpg"
            />
            <TeamMember
              name="Md. Fajlay Rabby"
              role="Head of Community"
              image="https://i.ibb.co.com/1XttHs2/IMG-20220107-150344-2.jpg"
            />
            <TeamMember
              name="Krypto"
              role="Product Designer"
              image="https://i.ibb.co.com/f8yV6G3/IMG-20220315-162332-2.jpg"
            />
          </div>
        </div>
      </section>
    </div>
  );
};

// Component for Values Grid
const ValuesGrid = () => {
  const values = [
    {
      number: "01",
      title: "Meritocratic Discovery",
      description: "The best tech rises based on quality, not marketing spend.",
      color: "bg-[var(--bg-accent)]",
    },
    {
      number: "02",
      title: "Constructive Feedback",
      description: "Our community thrives on helpful, actionable feedback.",
      color: "bg-purple-500",
    },
    {
      number: "03",
      title: "Inclusive Innovation",
      description: "We level the playing field for creators of all backgrounds.",
      color: "bg-pink-500",
    },
    {
      number: "04",
      title: "User Privacy First",
      description: "We never compromise on user privacy or data security.",
      color: "bg-green-500",
    },
    {
      number: "05",
      title: "Transparent Curation",
      description: "Our moderation and ranking processes are open.",
      color: "bg-yellow-500",
    },
    {
      number: "06",
      title: "Continuous Evolution",
      description: "We improve based on community needs.",
      color: "bg-red-500",
    },
  ];

  return (
    <section className="py-12">
      <div className="container mx-auto px-4 max-w-5xl">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
            What We Stand For
          </span>
          <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
            Our Core Values
          </h2>
          <p className="text-sm custom-text-secondary max-w-3xl mx-auto">
            The principles that guide our platform, community, and team.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {values.map((value, index) => (
            <ValueCard
              key={index}
              number={value.number}
              title={value.title}
              description={value.description}
              color={value.color}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

// Component for Value Cards
const ValueCard = ({ number, title, description, color }) => {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      whileInView={{ opacity: 1, scale: 1 }}
      whileHover={{ y: -5, transition: { type: "spring", stiffness: 300 } }}
      viewport={{ once: true }}
      transition={{ duration: 0.4 }}
      className="custom-bg-secondary border border-[var(--bg-accent)]/20 rounded-xl shadow-sm hover:shadow-lg transition-all tooltip tooltip-bottom"
      data-tip={title}
    >
      <div className="p-5">
        <div className="flex items-center gap-3 mb-3">
          <span className={`text-xs font-mono font-bold text-white ${color} px-2 py-1 rounded-md`}>
            {number}
          </span>
          <h3 className="text-lg font-bold custom-text-primary">{title}</h3>
        </div>
        <p className="text-sm custom-text-secondary">{description}</p>
      </div>
      <div className={`h-1 w-full ${color} opacity-70 transform scale-x-0 hover:scale-x-100 origin-left transition-transform duration-300`}></div>
    </motion.div>
  );
};

// Component for Team Members
const TeamMember = ({ name, role, image }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      whileHover={{ y: -5, transition: { type: "spring", stiffness: 300 } }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      className="text-center group tooltip tooltip-bottom"
      data-tip={`Learn more about ${name}`}
    >
      <div className="relative inline-block mb-4">
        <div className="absolute -inset-2 bg-gradient-to-tr from-[var(--bg-accent)] to-transparent rounded-full opacity-0 group-hover:opacity-20 transition-opacity blur-lg"></div>
        <img
          src={image}
          alt={name}
          className="w-32 h-32 rounded-full mx-auto object-cover border-2 border-[var(--bg-accent)]/20 shadow-md group-hover:shadow-lg transition-all"
        />
      </div>
      <h3 className="text-lg font-semibold custom-text-primary mb-1">{name}</h3>
      <p className="text-sm custom-text-secondary">{role}</p>
    </motion.div>
  );
};

export default About;