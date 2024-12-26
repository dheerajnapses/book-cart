import { Request, Response } from 'express';
import Address from '../models/Address'; // Import the Address model
import { response } from '../utils/responseHandler';
import User from '../models/User';

// Function to get address by userId
export const getAddressByUserId = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 

    if (!userId) {
      return response(res, 400, 'User not found');
    }

    // Find the address by userId
    const address = await User.findById(userId).populate('addresses');
    if (!address) {
      return response(res, 404, 'Address not found');
    }

    return response(res, 200, 'Address fetched successfully', address);
  } catch (error) {
    console.error(error);
    return response(res, 500, 'Error fetching address');
  }
};

export const createOrUpdateAddressByUserId = async (req: Request, res: Response) => {
  try {
    const userId = req?.id; 
    const { phoneNumber, addressLine1, addressLine2, city, state, pincode, addressId } = req.body;
    console.log(req.body);

    if (!userId) {
      return response(res, 400, 'User not found');
    }

    // Validate required fields
    if (!phoneNumber || !addressLine1 || !city || !state || !pincode) {
      return response(res, 400, 'All address fields are required');
    }

    // Check if an addressId is provided for update
    if (addressId) {
      // Find and update the existing address
      const existingAddress = await Address.findById(addressId);
      if (!existingAddress) {
        return response(res, 404, 'Address not found');
      }

      existingAddress.phoneNumber = phoneNumber;
      existingAddress.addressLine1 = addressLine1;
      existingAddress.addressLine2 = addressLine2;
      existingAddress.city = city;
      existingAddress.state = state;
      existingAddress.pincode = pincode;

      // Save the updated address
      await existingAddress.save();

      return response(res, 200, 'Address updated successfully', existingAddress);
    } else {
      // Create a new address if no addressId is provided
      const newAddress = new Address({
        user: userId,
        addressLine1,
        addressLine2,
        phoneNumber,
        city,
        state,
        pincode,
      });

      // Save the new address
      await newAddress.save();

      // Add the new address to the user's addresses array
      await User.findByIdAndUpdate(
        userId,
        { $push: { addresses: newAddress._id } },
        { new: true }
      );

      return response(res, 201, 'Address added successfully', newAddress);
    }
  } catch (error) {
    console.error(error);
    return response(res, 500, 'Error creating or updating address');
  }
};




