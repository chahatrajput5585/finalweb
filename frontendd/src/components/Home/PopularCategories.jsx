import React from "react";
import {
  MdOutlineDesignServices,
  MdOutlineWebhook,
  MdAccountBalance,
  MdOutlineAnimation,
} from "react-icons/md";
import { TbAppsFilled } from "react-icons/tb";
import { FaReact } from "react-icons/fa";
import { GiArtificialIntelligence } from "react-icons/gi";
import { IoGameController } from "react-icons/io5";

const PopularCategories = () => {
  const categories = [
    {
      id: 1,
      title: "Beauty & personal care",
      subTitle: "305 Open Shops",
      icon: <MdOutlineDesignServices />,
    },
    {
      id: 2,
      title: "Mobile Shop",
      subTitle: "500 Open Shops",
      icon: <TbAppsFilled />,
    },
    {
      id: 3,
      title: "Food & Beverage",
      subTitle: "200 Open Shops",
      icon: <MdOutlineWebhook />,
    },
    {
      id: 4,
      title: "Health & Welleness",
      subTitle: "1000+ Open Medicals",
      icon: <FaReact />,
    },
    {
      id: 5,
      title: "Home & Decor",
      subTitle: "150 Open Shops",
      icon: <MdAccountBalance />,
    },
    {
      id: 6,
      title: "Fashion",
      subTitle: "867 Open Shops",
      icon: <GiArtificialIntelligence />,
    },
    {
      id: 7,
      title: "Grocery",
      subTitle: "50 Open Shops",
      icon: <MdOutlineAnimation />,
    },
    {
      id: 8,
      title: "Fitness Gym",
      subTitle: "80 Open Gyms",
      icon: <IoGameController />,
    },
  ];
  return (
    <div className="categories">
      <h3>POPULAR CATEGORIES Shops</h3>
      <div className="banner">
        {categories.map((element) => {
          return (
            <div className="card" key={element.id}>
              <div className="icon">{element.icon}</div>
              <div className="text">
                <p>{element.title}</p>
                <p>{element.subTitle}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default PopularCategories;
