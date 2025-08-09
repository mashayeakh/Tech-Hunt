import { useState } from "react";
import { motion } from "framer-motion";
import { ChevronDown } from "lucide-react";

const FaqItem = ({ question, answer }) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <motion.div
      className="border-b border-[var(--bg-accent)]/20 py-4"
      initial={{ opacity: 0, y: 10 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      viewport={{ once: true }}
    >
      <button
        className="flex justify-between items-center w-full text-left tooltip tooltip-bottom"
        onClick={() => setIsOpen(!isOpen)}
        data-tip={isOpen ? "Collapse" : "Expand"}
      >
        <h3 className="text-lg font-semibold custom-text-primary">{question}</h3>
        <motion.span
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.3 }}
        >
          <ChevronDown size={20} className="custom-text-accent" />
        </motion.span>
      </button>
      <motion.div
        className="text-sm custom-text-secondary overflow-hidden"
        initial={{ height: 0, opacity: 0 }}
        animate={{ height: isOpen ? "auto" : 0, opacity: isOpen ? 1 : 0 }}
        transition={{ duration: 0.3 }}
      >
        <p className="py-2">{answer}</p>
      </motion.div>
    </motion.div>
  );
};

const FAQ = () => {
  const faqData = [
    {
      question: "How is Tech Hunt different from Product Hunt?",
      answer:
        "While inspired by Product Hunt, Tech Hunt focuses specifically on technology products like web apps, AI tools, software, and mobile applications. We've implemented a role-based system that ensures quality through community moderation, and offer unique features like membership tiers for product creators.",
    },
    {
      question: "Can I submit my product for free?",
      answer:
        "Yes! Basic users can submit one product for review. However, we offer premium memberships that allow for unlimited submissions and additional promotional features to help your product stand out.",
    },
    {
      question: "How does the moderation process work?",
      answer:
        "Submitted products go through a review by our moderator team who check for quality, relevance, and adherence to our community guidelines. This ensures that users discover genuinely valuable tools rather than promotional content.",
    },
    {
      question: "How can I become a moderator?",
      answer:
        "Active community members who consistently contribute quality reviews and help report inappropriate content may be invited to become moderators. Alternatively, you can apply for a moderator position through your profile settings.",
    },
    {
      question: "Do you offer discounts for startups or indie developers?",
      answer:
        "Yes! We have special coupon codes for indie developers and early-stage startups. These coupons provide discounts on our premium membership tiers to help new creators gain visibility.",
    },
  ];

  return (
    <section className="py-12 custom-bg-primary font-inter">
      <div className="container mx-auto px-4 max-w-5xl">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <span className="inline-block px-3 py-1 text-xs font-bold uppercase custom-bg-accent text-white rounded-full mb-4">
            FAQ
          </span>
          <h2 className="chakra text-3xl md:text-4xl font-bold custom-text-primary mb-4">
            Frequently Asked Questions
          </h2>
          <p className="text-sm custom-text-secondary max-w-2xl mx-auto">
            Everything you need to know about Tech Hunt and how to get started.
          </p>
        </motion.div>

        <div className="max-w-3xl mx-auto">
          {faqData.map((faq, index) => (
            <FaqItem key={index} question={faq.question} answer={faq.answer} />
          ))}
        </div>
      </div>
    </section>
  );
};

export default FAQ;